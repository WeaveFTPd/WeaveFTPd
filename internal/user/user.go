package user

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// StatLine matches userfile format: Files, Bytes, Meta
type StatLine struct {
	Files int64 `yaml:"files"`
	Bytes int64 `yaml:"bytes"`
	Meta  int64 `yaml:"meta"`
}

type User struct {
	Name         string         `yaml:"name"`
	Password     string         `yaml:"password"`
	UID          int            `yaml:"uid"`
	GID          int            `yaml:"gid"`
	Flags        string         `yaml:"flags"`
	Tagline      string         `yaml:"tagline"`
	MailboxID    string         `yaml:"-"` // Stable private identity, retained across renames.
	HomeRoot     string         `yaml:"home_root"`
	HomeDir      string         `yaml:"homedir"`
	CurrentDir   string         `yaml:"current_dir"` // Runtime: current FTP dir
	Added        int64          `yaml:"added"`
	LastLogin    int64          `yaml:"last_login"`
	PeriodAnchor int64          `yaml:"-"`
	FileModTime  int64          `yaml:"-"`
	Expires      int64          `yaml:"expires"`
	Credits      int64          `yaml:"credits"`
	Ratio        int            `yaml:"ratio"`
	Groups       map[string]int `yaml:"groups"`
	PrimaryGroup string         `yaml:"primary_group"` // Primary group for file ownership
	IPs          []string       `yaml:"ips"`

	// Throughput Stats (files, bytes, meta)
	AllUp   StatLine `yaml:"allup"`
	AllDn   StatLine `yaml:"alldn"`
	WkUp    StatLine `yaml:"wkup"`
	WkDn    StatLine `yaml:"wkdn"`
	DayUp   StatLine `yaml:"dayup"`
	DayDn   StatLine `yaml:"daydn"`
	MonthUp StatLine `yaml:"monthup"`
	MonthDn StatLine `yaml:"monthdn"`

	// Nuke Stats
	NukeStat StatLine `yaml:"nukestat"`

	// Slot Configuration
	LoginSlots         int   `yaml:"login_slots"`    // Max concurrent logins
	MaxSim             int   `yaml:"max_sim"`        // Max total concurrent transfers
	UploadSlots        int   `yaml:"upload_slots"`   // Max concurrent uploads
	DownloadSlots      int   `yaml:"download_slots"` // Max concurrent downloads
	WeeklyAllotment    int64 `yaml:"weekly_allotment"`
	GroupSlots         int   `yaml:"group_slots"`
	LeechSlots         int   `yaml:"leech_slots"`
	LoginSlotsSet      bool  `yaml:"-"`
	MaxSimSet          bool  `yaml:"-"`
	UploadSlotsSet     bool  `yaml:"-"`
	DownloadSlotsSet   bool  `yaml:"-"`
	WeeklyAllotmentSet bool  `yaml:"-"`
	GroupSlotsSet      bool  `yaml:"-"`
	LeechSlotsSet      bool  `yaml:"-"`

	// Raw userfile fields we preserve across load/save so imported glFTPD
	// accounts keep their original shape instead of being flattened.
	UserLine      string            `yaml:"-"`
	GeneralLine   string            `yaml:"-"`
	LoginsLine    string            `yaml:"-"`
	TimeframeLine string            `yaml:"-"`
	AddedBy       string            `yaml:"-"`
	CreditsExtra  string            `yaml:"-"`
	RatioExtra    string            `yaml:"-"`
	StatExtras    map[string]string `yaml:"-"`
	TimeFields    []string          `yaml:"-"`
}

var userStatLocks sync.Map
var userFileCache sync.Map

type cachedUserFile struct {
	user        *User
	userStamp   fileStamp
	passwdStamp fileStamp
}

type fileStamp struct {
	modTimeUnixNano int64
	size            int64
}

func userStatLock(name string) *sync.Mutex {
	lock, _ := userStatLocks.LoadOrStore(name, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func WithFileLock(name string, fn func() error) error {
	lock := userStatLock(name)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func userCacheKey(name, filePath string) string {
	if abs, err := filepath.Abs(filePath); err == nil {
		filePath = abs
	}
	return name + "\x00" + filepath.Clean(filePath)
}

func statFileStamp(filePath string) (fileStamp, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{modTimeUnixNano: info.ModTime().UnixNano(), size: info.Size()}, nil
}

func optionalFileStamp(filePath string) fileStamp {
	stamp, err := statFileStamp(filePath)
	if err != nil {
		return fileStamp{modTimeUnixNano: -1, size: -1}
	}
	return stamp
}

func cachedUser(name, filePath string, userStamp, passwdStamp fileStamp) (*User, bool) {
	value, ok := userFileCache.Load(userCacheKey(name, filePath))
	if !ok {
		return nil, false
	}
	entry, ok := value.(cachedUserFile)
	if !ok || entry.user == nil {
		return nil, false
	}
	if entry.userStamp != userStamp || entry.passwdStamp != passwdStamp {
		return nil, false
	}
	return cloneUser(entry.user), true
}

func storeCachedUser(name, filePath string, userStamp, passwdStamp fileStamp, u *User) {
	if u == nil {
		return
	}
	userFileCache.Store(userCacheKey(name, filePath), cachedUserFile{
		user:        cloneUser(u),
		userStamp:   userStamp,
		passwdStamp: passwdStamp,
	})
}

func invalidateCachedUser(name, filePath string) {
	userFileCache.Delete(userCacheKey(name, filePath))
}

func cloneUser(u *User) *User {
	if u == nil {
		return nil
	}
	cp := *u
	if u.Groups != nil {
		cp.Groups = make(map[string]int, len(u.Groups))
		for k, v := range u.Groups {
			cp.Groups[k] = v
		}
	}
	cp.IPs = append([]string(nil), u.IPs...)
	if u.StatExtras != nil {
		cp.StatExtras = make(map[string]string, len(u.StatExtras))
		for k, v := range u.StatExtras {
			cp.StatExtras[k] = v
		}
	}
	cp.TimeFields = append([]string(nil), u.TimeFields...)
	return &cp
}

func MutateAndSave(name string, groupMap map[string]int, mutate func(*User) error) (*User, error) {
	var updated *User
	err := WithFileLock(name, func() error {
		u, err := LoadUser(name, groupMap)
		if err != nil {
			return err
		}
		if mutate != nil {
			if err := mutate(u); err != nil {
				return err
			}
		}
		if err := u.saveLocked(); err != nil {
			return err
		}
		updated = u
		return nil
	})
	return updated, err
}

// LoadUser reads user file - supports userfile format
func LoadUser(name string, groupMap map[string]int) (*User, error) {
	// Use exact case - usernames are case-sensitive like weaveftpd
	var err error
	name, err = NormalizeName(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join("etc", "users", name)
	return loadUserFile(name, path, groupMap)
}

func LoadTemplate(name, templatePath string, groupMap map[string]int) (*User, error) {
	var err error
	name, err = NormalizeName(name)
	if err != nil {
		return nil, err
	}
	return loadUserFile(name, templatePath, groupMap)
}

func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("empty username")
	}
	if name == "." || name == ".." ||
		filepath.Base(name) != name ||
		strings.ContainsAny(name, "/\\: \t\r\n") {
		return "", fmt.Errorf("invalid username %q", name)
	}
	return name, nil
}

func validateUserName(name string) error {
	_, err := NormalizeName(name)
	return err
}

// passwdFilePath is where loadUserFile reads UID/GID from. Defaults to the
// conventional location; the daemon overrides it from config at startup via
// SetPasswdFilePath so a non-default passwd_file is honored (previously this was
// hardcoded, giving wrong UID/GID and a cache keyed to the wrong file).
var passwdFilePath = "etc/passwd"

// SetPasswdFilePath points user loading at the configured passwd file.
func SetPasswdFilePath(p string) {
	if p = strings.TrimSpace(p); p != "" {
		passwdFilePath = p
	}
}

func loadUserFile(name, path string, groupMap map[string]int) (*User, error) {
	path = filepath.Clean(path)
	userStamp, err := statFileStamp(path)
	if err != nil {
		return nil, err
	}
	passwdStamp := optionalFileStamp(passwdFilePath)
	if u, ok := cachedUser(name, path, userStamp, passwdStamp); ok {
		applyGroupMap(u, groupMap)
		return u, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("userfile %s is empty", name)
	}

	// Parse userfile format
	u := &User{
		Name:       name, // Keep original case
		Groups:     make(map[string]int),
		IPs:        []string{},
		UID:        1000, // default
		GID:        300,  // default
		StatExtras: make(map[string]string),
	}
	u.FileModTime = userStamp.modTimeUnixNano / int64(time.Second)

	// Load UID/GID from passwd file
	if passwdData, err := os.ReadFile(passwdFilePath); err == nil {
		lines := strings.Split(string(passwdData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) >= 4 && parts[0] == name {
				fmt.Sscanf(parts[2], "%d", &u.UID)
				fmt.Sscanf(parts[3], "%d", &u.GID)
				break
			}
		}
	}

	// Simple weaveftpd parser inline
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]
		switch cmd {
		case "USER":
			if len(parts) > 1 {
				u.UserLine = strings.Join(parts[1:], " ")
			}
		case "GENERAL":
			if len(parts) > 1 {
				u.GeneralLine = strings.Join(parts[1:], " ")
			}
		case "LOGINS":
			if len(parts) > 1 {
				u.LoginsLine = strings.Join(parts[1:], " ")
			}
			u.deriveLoginLimitsFromLine()
		case "HOMEDIR":
			if len(parts) > 1 {
				u.HomeRoot = parts[1]
			}
		case "FLAGS":
			if len(parts) > 1 {
				u.Flags = parts[1]
			}
		case "MAILBOX":
			if len(parts) == 2 {
				u.MailboxID = parts[1]
			}
		case "TAGLINE":
			if len(parts) > 1 {
				u.Tagline = strings.Join(parts[1:], " ")
			}
		case "DIR":
			if len(parts) > 1 {
				u.HomeDir = parts[1]
			}
		case "RATIO":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.Ratio)
			}
			if len(parts) > 2 {
				u.RatioExtra = strings.Join(parts[2:], " ")
			}
		case "CREDITS":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.Credits)
			}
			if len(parts) > 2 {
				u.CreditsExtra = strings.Join(parts[2:], " ")
			}
		case "ALLUP", "ALLDN", "WKUP", "WKDN", "DAYUP", "DAYDN", "MONTHUP", "MONTHDN":
			if len(parts) >= 4 {
				var files, bytes, meta int64
				fmt.Sscanf(parts[1], "%d", &files)
				fmt.Sscanf(parts[2], "%d", &bytes)
				fmt.Sscanf(parts[3], "%d", &meta)
				stat := StatLine{Files: files, Bytes: bytes, Meta: meta}

				switch cmd {
				case "ALLUP":
					u.AllUp = stat
				case "ALLDN":
					u.AllDn = stat
				case "WKUP":
					u.WkUp = stat
				case "WKDN":
					u.WkDn = stat
				case "DAYUP":
					u.DayUp = stat
				case "DAYDN":
					u.DayDn = stat
				case "MONTHUP":
					u.MonthUp = stat
				case "MONTHDN":
					u.MonthDn = stat
				}
				if len(parts) > 4 {
					u.StatExtras[cmd] = strings.Join(parts[4:], " ")
				}
			}
		case "NUKE":
			if len(parts) >= 4 {
				var last, times, bytes int64
				fmt.Sscanf(parts[1], "%d", &last)
				fmt.Sscanf(parts[2], "%d", &times)
				fmt.Sscanf(parts[3], "%d", &bytes)
				u.NukeStat = StatLine{Files: times, Bytes: bytes, Meta: last}
				if len(parts) > 4 {
					u.StatExtras[cmd] = strings.Join(parts[4:], " ")
				}
			}
		case "TIME":
			if len(parts) > 1 {
				u.TimeFields = append([]string(nil), parts[1:]...)
			}
			if len(parts) >= 3 {
				var lastOn int64
				fmt.Sscanf(parts[2], "%d", &lastOn)
				u.LastLogin = lastOn
			}
			if len(parts) >= 6 {
				var periodAnchor int64
				fmt.Sscanf(parts[5], "%d", &periodAnchor)
				u.PeriodAnchor = periodAnchor
			}
		case "ADDED":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.Added)
			}
			if len(parts) > 2 {
				u.AddedBy = strings.Join(parts[2:], " ")
			}
		case "EXPIRES":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.Expires)
			}
		case "GROUP":
			if len(parts) >= 2 {
				group := parts[1]
				isAdmin := 0
				if len(parts) > 2 {
					fmt.Sscanf(parts[2], "%d", &isAdmin)
				}
				u.Groups[group] = isAdmin
			}
		case "PRIMARY", "PRIMARY_GROUP":
			if len(parts) >= 2 {
				u.PrimaryGroup = parts[1]
			}
		case "IP":
			if len(parts) > 1 {
				u.IPs = append(u.IPs, parts[1])
			}
		case "UPLOADSLOTS":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.UploadSlots)
				u.UploadSlotsSet = true
			}
		case "DOWNLOADSLOTS":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.DownloadSlots)
				u.DownloadSlotsSet = true
			}
		case "LOGINSLOTS":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.LoginSlots)
				u.LoginSlotsSet = true
			}
		case "MAXSIM":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.MaxSim)
				u.MaxSimSet = true
			}
		case "WKLYALLOTMENT":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.WeeklyAllotment)
				u.WeeklyAllotmentSet = true
			}
		case "GROUPSLOTS":
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &u.GroupSlots)
				u.GroupSlotsSet = true
			}
			if len(parts) > 2 {
				fmt.Sscanf(parts[2], "%d", &u.LeechSlots)
				u.LeechSlotsSet = true
			}
		case "TIMEFRAME":
			if len(parts) > 1 {
				u.TimeframeLine = strings.Join(parts[1:], " ")
			}
		}
	}

	if u.HomeDir == "" {
		u.HomeDir = "/"
	}
	if u.HomeRoot == "" {
		u.HomeRoot = "/site"
	}
	u.CurrentDir = u.HomeDir
	if u.PrimaryGroup != "" {
		if _, ok := u.Groups[u.PrimaryGroup]; !ok {
			u.Groups[u.PrimaryGroup] = 0
		}
	}
	if u.UserLine == "" {
		u.UserLine = "Added by WeaveFTPd"
	}
	if u.GeneralLine == "" {
		u.GeneralLine = "0,120 -1 0 0"
	}
	if u.LoginsLine == "" {
		u.LoginsLine = "16 0 6 10"
	}
	if u.TimeframeLine == "" {
		u.TimeframeLine = "0 0"
	}
	if u.AddedBy == "" {
		u.AddedBy = "weaveftpd"
	}
	if u.LoginsLine != "" {
		u.deriveLoginLimitsFromLine()
	}
	if !u.LoginSlotsSet {
		u.LoginSlots = 16
		u.LoginSlotsSet = true
	}
	if err := validateLoadedUserfile(name, string(data), u); err != nil {
		return nil, err
	}

	storeCachedUser(name, path, userStamp, passwdStamp, u)
	applyGroupMap(u, groupMap)

	return u, nil
}

func applyGroupMap(u *User, groupMap map[string]int) {
	if u == nil || groupMap == nil {
		return
	}
	if u.PrimaryGroup != "" {
		if gid, ok := groupMap[u.PrimaryGroup]; ok {
			u.GID = gid
		}
		return
	}
	if len(u.Groups) == 0 {
		return
	}
	groups := make([]string, 0, len(u.Groups))
	for g := range u.Groups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	if gid, ok := groupMap[groups[0]]; ok {
		u.GID = gid
		u.PrimaryGroup = groups[0]
	}
}

func validateLoadedUserfile(name, raw string, u *User) error {
	safety := inspectUserfileSafety(raw)
	hasTraffic := u.AllUp.Files > 0 || u.AllUp.Bytes > 0 ||
		u.AllDn.Files > 0 || u.AllDn.Bytes > 0 ||
		u.WkUp.Files > 0 || u.WkUp.Bytes > 0 ||
		u.DayUp.Files > 0 || u.DayUp.Bytes > 0 ||
		u.MonthUp.Files > 0 || u.MonthUp.Bytes > 0
	if hasTraffic && safety.groups == 0 && safety.ips == 0 && safety.primaryGroup == "" && safety.ratio == 0 && safety.credits == 0 {
		return fmt.Errorf("userfile %s looks truncated: has stats but no GROUP/IP/account fields", name)
	}
	return nil
}

func (u *User) deriveLoginLimitsFromLine() {
	fields := strings.Fields(u.LoginsLine)
	if len(fields) < 4 {
		return
	}
	var loginSlots, maxSim, uploadSlots, downloadSlots int
	fmt.Sscanf(fields[0], "%d", &loginSlots)
	fmt.Sscanf(fields[1], "%d", &maxSim)
	fmt.Sscanf(fields[3], "%d", &uploadSlots)
	fmt.Sscanf(fields[2], "%d", &downloadSlots)
	if !u.LoginSlotsSet || u.LoginSlots == 0 {
		u.LoginSlots = loginSlots
		u.LoginSlotsSet = true
	}
	if !u.MaxSimSet {
		u.MaxSim = maxSim
		u.MaxSimSet = true
	}
	if !u.UploadSlotsSet || u.UploadSlots == 0 {
		u.UploadSlots = uploadSlots
		u.UploadSlotsSet = true
	}
	if !u.DownloadSlotsSet || u.DownloadSlots == 0 {
		u.DownloadSlots = downloadSlots
		u.DownloadSlotsSet = true
	}
}

func (u *User) syncLoginsLine() {
	if !u.LoginSlotsSet && u.LoginSlots == 0 {
		u.LoginSlots = 16
	}
	u.LoginsLine = fmt.Sprintf("%d %d %d %d", u.LoginSlots, u.MaxSim, u.DownloadSlots, u.UploadSlots)
}

// Save writes user back to userfile-format file
func (u *User) Save() error {
	lock := userStatLock(u.Name)
	lock.Lock()
	defer lock.Unlock()
	return u.saveLocked()
}

func (u *User) saveLocked() error {
	// Use exact case
	var err error
	u.Name, err = NormalizeName(u.Name)
	if err != nil {
		return err
	}
	path := filepath.Join("etc", "users", u.Name)
	if u.HomeRoot == "" {
		u.HomeRoot = "/site"
	}
	if u.HomeDir == "" {
		u.HomeDir = "/"
	}
	if u.Tagline == "" {
		u.Tagline = "No Tagline Set"
	}
	if u.Groups == nil {
		u.Groups = make(map[string]int)
	}
	if u.PrimaryGroup != "" {
		if _, ok := u.Groups[u.PrimaryGroup]; !ok {
			u.Groups[u.PrimaryGroup] = 0
		}
	}
	if u.UserLine == "" {
		u.UserLine = "Added by WeaveFTPd"
	}
	if u.GeneralLine == "" {
		u.GeneralLine = "0,120 -1 0 0"
	}
	if u.LoginsLine == "" {
		u.LoginsLine = "16 0 6 10"
	}
	if u.TimeframeLine == "" {
		u.TimeframeLine = "0 0"
	}
	if u.AddedBy == "" {
		u.AddedBy = "weaveftpd"
	}
	if u.StatExtras == nil {
		u.StatExtras = make(map[string]string)
	}
	u.syncLoginsLine()

	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}

	currentBytes, mode, currentExists, err := readExistingUserfileForSave(path)
	if err != nil {
		return err
	}
	// An older session snapshot must not erase or replace an assigned mailbox.
	for _, line := range strings.Split(string(currentBytes), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "MAILBOX" {
			u.MailboxID = fields[1]
			break
		}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "USER %s\n", u.UserLine)
	fmt.Fprintf(&buf, "GENERAL %s\n", u.GeneralLine)
	fmt.Fprintf(&buf, "LOGINS %s\n", u.LoginsLine)
	fmt.Fprintf(&buf, "TIMEFRAME %s\n", u.TimeframeLine)
	fmt.Fprintf(&buf, "FLAGS %s\n", u.Flags)
	fmt.Fprintf(&buf, "TAGLINE %s\n", u.Tagline)
	if u.MailboxID != "" {
		fmt.Fprintf(&buf, "MAILBOX %s\n", u.MailboxID)
	}
	fmt.Fprintf(&buf, "HOMEDIR %s\n", u.HomeRoot)
	fmt.Fprintf(&buf, "DIR %s\n", u.HomeDir)
	fmt.Fprintf(&buf, "ADDED %d %s\n", u.Added, u.AddedBy)
	fmt.Fprintf(&buf, "EXPIRES %d\n", u.Expires)
	writeValueLine(&buf, "CREDITS", u.Credits, u.CreditsExtra)
	writeValueLine(&buf, "RATIO", int64(u.Ratio), u.RatioExtra)
	fmt.Fprintf(&buf, "LOGINSLOTS %d\n", u.LoginSlots)
	fmt.Fprintf(&buf, "MAXSIM %d\n", u.MaxSim)
	fmt.Fprintf(&buf, "UPLOADSLOTS %d\n", u.UploadSlots)
	fmt.Fprintf(&buf, "DOWNLOADSLOTS %d\n", u.DownloadSlots)
	fmt.Fprintf(&buf, "WKLYALLOTMENT %d\n", u.WeeklyAllotment)
	fmt.Fprintf(&buf, "GROUPSLOTS %d %d\n", u.GroupSlots, u.LeechSlots)
	writeStatLine(&buf, "ALLUP", u.AllUp, u.StatExtras["ALLUP"])
	writeStatLine(&buf, "ALLDN", u.AllDn, u.StatExtras["ALLDN"])
	writeStatLine(&buf, "WKUP", u.WkUp, u.StatExtras["WKUP"])
	writeStatLine(&buf, "WKDN", u.WkDn, u.StatExtras["WKDN"])
	writeStatLine(&buf, "DAYUP", u.DayUp, u.StatExtras["DAYUP"])
	writeStatLine(&buf, "DAYDN", u.DayDn, u.StatExtras["DAYDN"])
	writeStatLine(&buf, "MONTHUP", u.MonthUp, u.StatExtras["MONTHUP"])
	writeStatLine(&buf, "MONTHDN", u.MonthDn, u.StatExtras["MONTHDN"])
	writeNukeLine(&buf, u.NukeStat, u.StatExtras["NUKE"])
	writeTimeLine(&buf, u.TimeFields, u.LastLogin, u.PeriodAnchor)

	if u.PrimaryGroup != "" {
		fmt.Fprintf(&buf, "PRIMARY_GROUP %s\n", u.PrimaryGroup)
	}

	groups := make([]string, 0, len(u.Groups))
	for group := range u.Groups {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	for _, group := range groups {
		fmt.Fprintf(&buf, "GROUP %s %d\n", group, u.Groups[group])
	}

	ips := append([]string(nil), u.IPs...)
	sort.Strings(ips)
	for _, ip := range ips {
		fmt.Fprintf(&buf, "IP %s\n", ip)
	}

	if err := validateUserfileRewrite(path, currentBytes, currentExists, buf.String()); err != nil {
		return err
	}

	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := file.Write(buf.Bytes()); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	invalidateCachedUser(u.Name, path)
	return nil
}

func readExistingUserfileForSave(path string) ([]byte, os.FileMode, bool, error) {
	mode := os.FileMode(0600)
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, mode, false, nil
		}
		return nil, mode, false, err
	}
	mode = st.Mode().Perm()
	currentBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, mode, false, err
	}
	return currentBytes, mode, true, nil
}

type userfileSafety struct {
	groups       int
	ips          int
	ratio        int64
	credits      int64
	hasRatio     bool
	hasCredits   bool
	hasTraffic   bool
	stats        map[string]StatLine
	primaryGroup string
}

func validateUserfileRewrite(path string, currentBytes []byte, currentExists bool, next string) error {
	if !currentExists {
		return nil
	}
	current := inspectUserfileSafety(string(currentBytes))
	if current.hasTraffic && current.groups == 0 && current.ips == 0 && current.primaryGroup == "" && current.ratio == 0 && current.credits == 0 {
		return fmt.Errorf("refusing unsafe userfile save for %s: current file looks truncated", filepath.Base(path))
	}
	if current.groups == 0 && current.ips == 0 && !current.hasRatio && !current.hasCredits && current.primaryGroup == "" && !current.hasTraffic {
		return nil
	}
	replacement := inspectUserfileSafety(next)
	if current.groups > 0 && replacement.groups == 0 {
		return fmt.Errorf("refusing unsafe userfile save for %s: would remove all GROUP lines", filepath.Base(path))
	}
	if current.ips > 0 && replacement.ips == 0 {
		return fmt.Errorf("refusing unsafe userfile save for %s: would remove all IP lines", filepath.Base(path))
	}
	if current.primaryGroup != "" && replacement.primaryGroup == "" {
		return fmt.Errorf("refusing unsafe userfile save for %s: would remove PRIMARY_GROUP", filepath.Base(path))
	}
	if current.hasRatio && current.ratio > 0 && (!replacement.hasRatio || replacement.ratio == 0) {
		return fmt.Errorf("refusing unsafe userfile save for %s: would reset RATIO from %d to 0", filepath.Base(path), current.ratio)
	}
	if current.hasCredits && current.credits > 0 && (!replacement.hasCredits || (replacement.credits == 0 && !statIncreased(replacement.stats["ALLDN"], current.stats["ALLDN"]))) {
		return fmt.Errorf("refusing unsafe userfile save for %s: would reset CREDITS from %d to 0", filepath.Base(path), current.credits)
	}
	for key, currentStat := range current.stats {
		if currentStat.Files == 0 && currentStat.Bytes == 0 && currentStat.Meta == 0 {
			continue
		}
		replacementStat, ok := replacement.stats[key]
		if !ok {
			return fmt.Errorf("refusing unsafe userfile save for %s: would remove %s", filepath.Base(path), key)
		}
		switch key {
		case "ALLUP", "ALLDN":
			if replacementStat.Files < currentStat.Files || replacementStat.Bytes < currentStat.Bytes {
				return fmt.Errorf("refusing unsafe userfile save for %s: would reduce %s from %d/%d to %d/%d", filepath.Base(path), key, currentStat.Files, currentStat.Bytes, replacementStat.Files, replacementStat.Bytes)
			}
		}
	}
	return nil
}

func statIncreased(next, current StatLine) bool {
	return next.Files > current.Files || next.Bytes > current.Bytes || next.Meta > current.Meta
}

func inspectUserfileSafety(text string) userfileSafety {
	out := userfileSafety{stats: make(map[string]StatLine)}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "GROUP":
			if len(fields) >= 2 {
				out.groups++
			}
		case "IP":
			if len(fields) >= 2 {
				out.ips++
			}
		case "PRIMARY", "PRIMARY_GROUP":
			if len(fields) >= 2 {
				out.primaryGroup = fields[1]
			}
		case "RATIO":
			if len(fields) >= 2 {
				if value, err := parseFirstInt64(fields[1]); err == nil {
					out.ratio = value
					out.hasRatio = true
				}
			}
		case "CREDITS":
			if len(fields) >= 2 {
				if value, err := parseFirstInt64(fields[1]); err == nil {
					out.credits = value
					out.hasCredits = true
				}
			}
		case "ALLUP", "ALLDN", "WKUP", "WKDN", "DAYUP", "DAYDN", "MONTHUP", "MONTHDN":
			if len(fields) >= 4 {
				files, filesErr := parseFirstInt64(fields[1])
				bytes, bytesErr := parseFirstInt64(fields[2])
				meta, metaErr := parseFirstInt64(fields[3])
				if (filesErr == nil && files > 0) || (bytesErr == nil && bytes > 0) {
					out.hasTraffic = true
				}
				if filesErr == nil && bytesErr == nil && metaErr == nil {
					out.stats[fields[0]] = StatLine{Files: files, Bytes: bytes, Meta: meta}
				}
			}
		}
	}
	return out
}

func parseFirstInt64(raw string) (int64, error) {
	var value int64
	_, err := fmt.Sscanf(raw, "%d", &value)
	return value, err
}

// UpdateStats increments throughput metrics and manages credits
func (u *User) UpdateStats(bytes int64, isUpload bool) {
	u.UpdateStatsWithCredits(bytes, isUpload, true)
}

func sameLocalDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func sameLocalMonth(a, b time.Time) bool {
	ay, am, _ := a.Date()
	by, bm, _ := b.Date()
	return ay == by && am == bm
}

func sameISOWeek(a, b time.Time) bool {
	ay, aw := a.ISOWeek()
	by, bw := b.ISOWeek()
	return ay == by && aw == bw
}

// ResetTransferStatPeriodsIfDue resets day/week/month transfer stats when the
// persisted stat anchor belongs to an older period than now.
func (u *User) ResetTransferStatPeriodsIfDue(now time.Time) bool {
	if u == nil {
		return false
	}
	anchor := u.PeriodAnchor
	if anchor <= 0 {
		anchor = u.FileModTime
	}
	if anchor <= 0 {
		anchor = u.LastLogin
	}
	if anchor <= 0 {
		return false
	}
	prev := time.Unix(anchor, 0).In(now.Location())
	changed := false
	if !sameLocalDay(prev, now) {
		u.DayUp = StatLine{}
		u.DayDn = StatLine{}
		changed = true
	}
	if !sameISOWeek(prev, now) {
		u.WkUp = StatLine{}
		u.WkDn = StatLine{}
		changed = true
	}
	if !sameLocalMonth(prev, now) {
		u.MonthUp = StatLine{}
		u.MonthDn = StatLine{}
		changed = true
	}
	if changed {
		u.PeriodAnchor = now.Unix()
	}
	return changed
}

func saturatingCreditGain(bytes int64, ratio int) int64 {
	if bytes <= 0 || ratio <= 0 {
		return 0
	}
	r := int64(ratio)
	if bytes > math.MaxInt64/r {
		return math.MaxInt64
	}
	return bytes * r
}

func saturatingCreditAdd(current, delta int64) int64 {
	if delta <= 0 {
		return current
	}
	if current > math.MaxInt64-delta {
		return math.MaxInt64
	}
	return current + delta
}

// UpdateStatsWithCredits increments throughput metrics and optionally applies
// ratio credits. Free sections such as speedtest still count traffic, but do
// not add upload credits or charge download credits.
func (u *User) UpdateStatsWithCredits(bytes int64, isUpload bool, applyCredits bool) {
	now := time.Now()
	lock := userStatLock(u.Name)
	lock.Lock()
	defer lock.Unlock()

	current := u
	if latest, err := LoadUser(u.Name, nil); err == nil && latest != nil {
		current = latest
	}
	current.ResetTransferStatPeriodsIfDue(now)
	if current.PeriodAnchor <= 0 {
		current.PeriodAnchor = now.Unix()
	}
	if isUpload {
		current.AllUp.Files++
		current.AllUp.Bytes += bytes
		current.WkUp.Files++
		current.WkUp.Bytes += bytes
		current.DayUp.Files++
		current.DayUp.Bytes += bytes
		current.MonthUp.Files++
		current.MonthUp.Bytes += bytes

		if applyCredits && current.Ratio > 0 {
			current.Credits = saturatingCreditAdd(current.Credits, saturatingCreditGain(bytes, current.Ratio))
		}
	} else {
		current.AllDn.Files++
		current.AllDn.Bytes += bytes
		current.WkDn.Files++
		current.WkDn.Bytes += bytes
		current.DayDn.Files++
		current.DayDn.Bytes += bytes
		current.MonthDn.Files++
		current.MonthDn.Bytes += bytes

		if applyCredits && current.Ratio > 0 {
			current.Credits -= bytes
			if current.Credits < 0 {
				current.Credits = 0
			}
		}
	}
	if err := current.saveLocked(); err != nil {
		log.Printf("[USER] failed to persist stats for %s: %v", u.Name, err)
	} else {
		current.FileModTime = now.Unix()
	}
	u.Credits = current.Credits
	u.AllUp = current.AllUp
	u.AllDn = current.AllDn
	u.WkUp = current.WkUp
	u.WkDn = current.WkDn
	u.DayUp = current.DayUp
	u.DayDn = current.DayDn
	u.MonthUp = current.MonthUp
	u.MonthDn = current.MonthDn
	u.PeriodAnchor = current.PeriodAnchor
	u.FileModTime = current.FileModTime
}

func (u *User) HasFlag(flag string) bool {
	return strings.Contains(u.Flags, flag)
}

func (u *User) IsInGroup(group string) bool {
	if u.PrimaryGroup == group {
		return true
	}
	if u.Groups == nil {
		return false
	}
	_, ok := u.Groups[group]
	return ok
}

func (u *User) IsGroupAdmin(group string) bool {
	if u.Groups == nil {
		return false
	}
	val, ok := u.Groups[group]
	return ok && val == 1
}

func (u *User) IsExpired() bool {
	if u.Expires == 0 {
		return false
	}
	return u.Expires < time.Now().Unix()
}

func writeValueLine(file io.Writer, key string, value int64, extra string) {
	if extra != "" {
		fmt.Fprintf(file, "%s %d %s\n", key, value, extra)
		return
	}
	fmt.Fprintf(file, "%s %d\n", key, value)
}

func writeStatLine(file io.Writer, key string, stat StatLine, extra string) {
	if extra != "" {
		fmt.Fprintf(file, "%s %d %d %d %s\n", key, stat.Files, stat.Bytes, stat.Meta, extra)
		return
	}
	fmt.Fprintf(file, "%s %d %d %d\n", key, stat.Files, stat.Bytes, stat.Meta)
}

func writeTimeLine(file io.Writer, fields []string, lastLogin int64, periodAnchor int64) {
	if len(fields) == 0 {
		if periodAnchor > 0 {
			fmt.Fprintf(file, "TIME %d %d 0 0 %d\n", 0, lastLogin, periodAnchor)
			return
		}
		fmt.Fprintf(file, "TIME %d %d 0 0\n", 0, lastLogin)
		return
	}
	copied := append([]string(nil), fields...)
	for len(copied) < 2 {
		copied = append(copied, "0")
	}
	copied[1] = fmt.Sprintf("%d", lastLogin)
	if periodAnchor > 0 {
		for len(copied) < 5 {
			copied = append(copied, "0")
		}
		copied[4] = fmt.Sprintf("%d", periodAnchor)
	}
	fmt.Fprintf(file, "TIME %s\n", strings.Join(copied, " "))
}

func writeNukeLine(file io.Writer, stat StatLine, extra string) {
	if extra != "" {
		fmt.Fprintf(file, "NUKE %d %d %d %s\n", stat.Meta, stat.Files, stat.Bytes, extra)
		return
	}
	fmt.Fprintf(file, "NUKE %d %d %d\n", stat.Meta, stat.Files, stat.Bytes)
}

func (u *User) IsDisabled() bool {
	return u.HasFlag("6")
}

func (u *User) IPAllowed(remoteIP string) bool {
	if len(u.IPs) == 0 {
		return false
	}
	for _, mask := range u.IPs {
		hostMask := strings.TrimSpace(mask)
		if strings.Contains(hostMask, "@") {
			parts := strings.SplitN(hostMask, "@", 2)
			hostMask = parts[1]
		}
		if hostMask == "*" || hostMask == remoteIP {
			return true
		}
		if ok, _ := pathpkg.Match(hostMask, remoteIP); ok {
			return true
		}
	}
	return false
}

func (u *User) HasEnoughCredits(fileBytes int64) bool {
	if u.Ratio == 0 {
		return true
	}
	return u.Credits >= fileBytes
}

func (u *User) HasDownloadAccess() bool {
	return u.HasFlag("3")
}

func (u *User) CanDownload(section string, fileBytes int64) bool {
	if !u.HasDownloadAccess() {
		return false
	}
	return u.HasEnoughCredits(fileBytes)
}
