package core

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"weaveftpd/internal/user"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

var passwdFileMu sync.RWMutex

// In-memory cache of the parsed passwd file. The login path calls
// LoadPasswdFile on every PASS; without this cache every login re-reads and
// re-parses the whole file from disk, which becomes a bottleneck during a race
// when many connections log in at once. The cache is keyed by path+mtime+size
// and is cleared explicitly whenever the file is rewritten.
var (
	passwdCacheMu   sync.Mutex
	passwdCachePath string
	passwdCacheMod  time.Time
	passwdCacheSize int64
	passwdCacheMap  map[string]string
)

// LoadPasswdFile reads standard /etc/passwd. The returned map is read-only and
// may be shared with other callers; do not mutate it.
func LoadPasswdFile(path string) (map[string]string, error) {
	if st, err := os.Stat(path); err == nil {
		passwdCacheMu.Lock()
		if passwdCacheMap != nil && passwdCachePath == path &&
			passwdCacheMod.Equal(st.ModTime()) && passwdCacheSize == st.Size() {
			cached := passwdCacheMap
			passwdCacheMu.Unlock()
			return cached, nil
		}
		passwdCacheMu.Unlock()
	}

	passwdFileMu.RLock()
	file, err := os.Open(path)
	if err != nil {
		passwdFileMu.RUnlock()
		return nil, err
	}
	passwds := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			passwds[parts[0]] = parts[1]
		}
	}
	scanErr := scanner.Err()
	_ = file.Close()
	passwdFileMu.RUnlock()
	if scanErr != nil {
		return passwds, scanErr
	}

	if st, err := os.Stat(path); err == nil {
		passwdCacheMu.Lock()
		passwdCachePath = path
		passwdCacheMod = st.ModTime()
		passwdCacheSize = st.Size()
		passwdCacheMap = passwds
		passwdCacheMu.Unlock()
	}
	return passwds, nil
}

// clearPasswdCache forces the next LoadPasswdFile to re-read from disk. Called
// after any write to the passwd file.
func clearPasswdCache() {
	passwdCacheMu.Lock()
	passwdCacheMap = nil
	passwdCacheMu.Unlock()
}

// Short-lived cache of successful logins so a burst of connections from the
// same racer (cbftp opens a control connection per slot at race start) doesn't
// run bcrypt on every one. Only successes are cached, keyed by
// username + a process-salted SHA-256 of the plaintext (never the plaintext
// itself), so the cached value is useless outside this process.
var (
	authCacheMu   sync.Mutex
	authCache     = map[string]authCacheEntry{}
	authCacheSalt [16]byte
)

type authCacheEntry struct {
	plainHash  [32]byte
	storedHash string
	expiry     time.Time
}

const authCacheTTL = 60 * time.Second

func init() {
	_, _ = rand.Read(authCacheSalt[:])
}

func authPlainHash(username, plaintext string) [32]byte {
	h := sha256.New()
	h.Write(authCacheSalt[:])
	h.Write([]byte(username))
	h.Write([]byte{0})
	h.Write([]byte(plaintext))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func invalidateAuthUser(username string) {
	authCacheMu.Lock()
	delete(authCache, username)
	authCacheMu.Unlock()
}

// VerifyPasswordCached verifies a login password with a short-lived success
// cache to avoid running bcrypt on every connection in a login burst. Falls
// back to the full VerifyPassword (and caches the result) on a miss.
func VerifyPasswordCached(username, plaintext, hash string) bool {
	ph := authPlainHash(username, plaintext)
	now := time.Now()
	authCacheMu.Lock()
	if e, ok := authCache[username]; ok && e.expiry.After(now) && e.storedHash == hash && e.plainHash == ph {
		authCacheMu.Unlock()
		return true
	}
	authCacheMu.Unlock()

	if !VerifyPassword(plaintext, hash) {
		return false
	}
	authCacheMu.Lock()
	authCache[username] = authCacheEntry{plainHash: ph, storedHash: hash, expiry: now.Add(authCacheTTL)}
	authCacheMu.Unlock()
	return true
}

// VerifyPassword checks plaintext password against a hash.
// Supported format:
//   - bcrypt: $2a$/$2b$/$2y$
//   - glFTPD PBKDF2-HMAC-SHA1: $<8 hex salt>$<40 hex digest>
//
// Everything else is rejected. Older builds accepted unknown $-prefixed
// hashes, but that effectively let any password through for those accounts.
func VerifyPassword(plaintext, hash string) bool {
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
	}
	if verifyLegacyGlftpdHash(plaintext, hash) {
		return true
	}
	return false
}

func IsLegacyGlftpdHash(hash string) bool {
	if len(hash) != 50 || !strings.HasPrefix(hash, "$") {
		return false
	}
	parts := strings.Split(hash, "$")
	return len(parts) == 3 && parts[0] == "" && len(parts[1]) == 8 && len(parts[2]) == 40
}

func verifyLegacyGlftpdHash(plaintext, hash string) bool {
	if !IsLegacyGlftpdHash(hash) {
		return false
	}
	parts := strings.Split(hash, "$")
	salt, err := hex.DecodeString(parts[1])
	if err != nil || len(salt) != 4 {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil || len(want) != sha1.Size {
		return false
	}
	got := pbkdf2.Key([]byte(plaintext), salt, 100, sha1.Size, sha1.New)
	return hmac.Equal(got, want)
}

// HashPassword creates a bcrypt hash (default cost 10).
func HashPassword(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), 10)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// UpgradeLegacyPasswordHash rewrites a verified legacy glFTPD hash to bcrypt.
// Returns true when an upgrade was performed.
func UpgradeLegacyPasswordHash(username, plaintext, currentHash, path string) (bool, error) {
	if !IsLegacyGlftpdHash(currentHash) {
		return false, nil
	}
	bcryptHash, err := HashPassword(plaintext)
	if err != nil {
		return false, err
	}
	if err := AddUserToPasswd(username, bcryptHash, path); err != nil {
		return false, err
	}
	return true, nil
}

// LoadGroupFile reads standard /etc/group file (groupname:desc:gid:slots)
func LoadGroupFile(path string) map[string]int {
	groupMap := make(map[string]int)
	file, err := os.Open(path)
	if err != nil {
		return groupMap
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			groupName := parts[0]
			var gid int
			fmt.Sscanf(parts[2], "%d", &gid)
			groupMap[groupName] = gid
		}
	}
	return groupMap
}

// AddGroupToFile appends a group to /etc/group file
func AddGroupToFile(groupName string, desc string, gid int) error {
	var err error
	groupName, err = normalizeSiteGroupName(groupName)
	if err != nil {
		return err
	}
	desc = sanitizeGroupDescription(desc)

	const groupPath = "etc/group"
	passwdFileMu.Lock()
	defer passwdFileMu.Unlock()

	mode := os.FileMode(0644)
	if st, err := os.Stat(groupPath); err == nil {
		mode = st.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	existing, err := os.ReadFile(groupPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	buf := existing
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	buf = append(buf, []byte(fmt.Sprintf("%s:%s:%d:\n", groupName, desc, gid))...)
	return atomicWriteFile(groupPath, buf, mode)
}

// RemoveGroupFromFile drops a group line from etc/group, rewriting the file
// atomically. Without this, GRPDEL only removed the per-group config file and
// the group reappeared from etc/group on the next restart/login.
func RemoveGroupFromFile(groupName string) error {
	var err error
	groupName, err = normalizeSiteGroupName(groupName)
	if err != nil {
		return err
	}

	const groupPath = "etc/group"
	passwdFileMu.Lock()
	defer passwdFileMu.Unlock()

	mode := os.FileMode(0644)
	if st, err := os.Stat(groupPath); err == nil {
		mode = st.Mode().Perm()
	} else if os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
	existing, err := os.ReadFile(groupPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(existing), "\n")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if strings.HasPrefix(line, groupName+":") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return nil
	}
	return atomicWriteFile(groupPath, []byte(strings.Join(kept, "\n")), mode)
}

func sanitizeGroupDescription(desc string) string {
	desc = strings.TrimSpace(desc)
	desc = strings.NewReplacer(":", " ", "\r", " ", "\n", " ").Replace(desc)
	desc = strings.Join(strings.Fields(desc), " ")
	return desc
}

// Password and user management functions

// Min helper function

// GetUsernameByUID looks up username from UID in passwd file
func GetUsernameByUID(uid int, config *Config) string {
	passwdFileMu.RLock()
	defer passwdFileMu.RUnlock()

	file, err := os.Open(config.PasswdFile)
	if err != nil {
		return fmt.Sprintf("%d", uid)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 1 {
			// Try both: exact UID match and username as fallback
			if len(parts) >= 3 {
				var fileUID int
				fmt.Sscanf(parts[2], "%d", &fileUID)
				if fileUID == uid {
					return parts[0]
				}
			}
		}
	}
	return fmt.Sprintf("%d", uid)
}

// GetGroupnameByGID looks up groupname from GID using the groupMap
func GetGroupnameByGID(gid int, groupMap map[string]int) string {
	// Reverse lookup: find groupname that maps to this GID
	for groupName, groupGID := range groupMap {
		if groupGID == gid {
			return groupName
		}
	}
	return fmt.Sprintf("%d", gid)
}

// AddUserToPasswd appends a new user entry to the passwd file.
// If the user already exists, it replaces the hash.
func AddUserToPasswd(username, hash, path string) error {
	var err error
	username, err = user.NormalizeName(username)
	if err != nil {
		return err
	}

	passwdFileMu.Lock()
	defer passwdFileMu.Unlock()

	mode := os.FileMode(0600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(string(existing), "\n")

	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, username+":") {
			lines[i] = formatPasswdLine(username, hash, line)
			found = true
			break
		}
	}
	if !found {
		newLine := formatPasswdLine(username, hash, "")
		// Remove trailing empty line before appending
		for len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(lines, newLine)
	}

	next := []byte(strings.Join(lines, "\n") + "\n")
	if err := writeAuthFileWithDashBackup(path, existing, next, mode); err != nil {
		return err
	}
	clearPasswdCache()
	invalidateAuthUser(username)
	return nil
}

func formatPasswdLine(username, hash, existingLine string) string {
	uid := "100"
	gid := "300"
	gecos := "0"
	home := "/site"
	shell := "/bin/false"

	if existingLine != "" {
		parts := strings.Split(existingLine, ":")
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			uid = parts[2]
		}
		if len(parts) >= 4 && strings.TrimSpace(parts[3]) != "" {
			gid = parts[3]
		}
		if len(parts) >= 5 && strings.TrimSpace(parts[4]) != "" {
			gecos = parts[4]
		}
		if len(parts) >= 6 && strings.TrimSpace(parts[5]) != "" {
			home = parts[5]
		}
		if len(parts) >= 7 && strings.TrimSpace(parts[6]) != "" {
			shell = parts[6]
		}
	}

	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s", username, hash, uid, gid, gecos, home, shell)
}

// RemoveUserFromPasswd removes a user entry from the passwd file.
func RemoveUserFromPasswd(username, path string) error {
	var err error
	username, err = user.NormalizeName(username)
	if err != nil {
		return err
	}

	passwdFileMu.Lock()
	defer passwdFileMu.Unlock()

	mode := os.FileMode(0600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(existing), "\n")

	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, username+":") {
			kept = append(kept, line)
		}
	}

	if err := writeAuthFileWithDashBackup(path, existing, []byte(strings.Join(kept, "\n")), mode); err != nil {
		return err
	}
	clearPasswdCache()
	invalidateAuthUser(username)
	return nil
}

// RenameUserInPasswd renames a passwd entry while preserving the existing hash and fields.
func RenameUserInPasswd(oldUsername, newUsername, path string) error {
	var err error
	oldUsername, err = user.NormalizeName(oldUsername)
	if err != nil {
		return err
	}
	newUsername, err = user.NormalizeName(newUsername)
	if err != nil {
		return err
	}

	passwdFileMu.Lock()
	defer passwdFileMu.Unlock()

	mode := os.FileMode(0600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(existing), "\n")
	if oldUsername != newUsername {
		for _, line := range lines {
			if strings.HasPrefix(line, newUsername+":") {
				return fmt.Errorf("user %s already exists in passwd", newUsername)
			}
		}
	}
	changed := false
	for i, line := range lines {
		if !strings.HasPrefix(line, oldUsername+":") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) == 0 {
			continue
		}
		parts[0] = newUsername
		lines[i] = strings.Join(parts, ":")
		changed = true
		break
	}
	if !changed {
		return fmt.Errorf("user %s not found in passwd", oldUsername)
	}
	if err := writeAuthFileWithDashBackup(path, existing, []byte(strings.Join(lines, "\n")), mode); err != nil {
		return err
	}
	clearPasswdCache()
	invalidateAuthUser(oldUsername)
	invalidateAuthUser(newUsername)
	return nil
}

func writeAuthFileWithDashBackup(path string, existing, next []byte, mode os.FileMode) error {
	_ = existing
	return atomicWriteFile(path, next, mode)
}
