package core

import (
	"net"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"weaveftpd/internal/acl"
	"weaveftpd/internal/plugin"
)

type sessionSnapshot struct {
	ID                uint64
	User              string
	PrimaryGroup      string
	Flags             string
	Remote            string
	CurrentDir        string
	StartedAt         time.Time
	LastCommandAt     time.Time
	LoggedIn          bool
	TransferDirection string
	TransferPath      string
	TransferBytes     int64
	TransferStartedAt time.Time
	TransferSlaveName string
	TransferSlaveIdx  int32
}

var (
	nextSessionID              atomic.Uint64
	activeSessions             sync.Map
	transferPathReservationsMu sync.Mutex
	activeUploadReservations   = map[string]*uploadPathState{}
	activeDownloadPaths        = map[string]int{}
)

func registerSession(s *Session) uint64 {
	id := nextSessionID.Add(1)
	s.ID = id
	s.controlTransport = s.Conn
	s.remoteAddress = remoteAddrString(s.Conn)
	activeSessions.Store(id, s)
	return id
}

func unregisterSession(id uint64) {
	activeSessions.Delete(id)
}

func reserveUploadPath(filePath string) bool {
	cleanPath := path.Clean(filePath)
	if cleanPath == "." || cleanPath == "/" {
		return false
	}
	transferPathReservationsMu.Lock()
	defer transferPathReservationsMu.Unlock()
	if _, exists := activeUploadReservations[cleanPath]; exists || activeDownloadPaths[cleanPath] > 0 {
		return false
	}
	activeUploadReservations[cleanPath] = &uploadPathState{done: make(chan struct{})}
	return true
}

func releaseUploadPath(filePath string) {
	cleanPath := path.Clean(filePath)
	if cleanPath == "." || cleanPath == "/" {
		return
	}
	transferPathReservationsMu.Lock()
	if state := activeUploadReservations[cleanPath]; state != nil {
		state.finish(false)
	}
	delete(activeUploadReservations, cleanPath)
	transferPathReservationsMu.Unlock()
}

func uploadPathReserved(filePath string) bool {
	cleanPath := path.Clean(filePath)
	if cleanPath == "." || cleanPath == "/" {
		return false
	}
	transferPathReservationsMu.Lock()
	_, ok := activeUploadReservations[cleanPath]
	transferPathReservationsMu.Unlock()
	return ok
}

func reserveDownloadPath(filePath string) bool {
	_, ok := reserveDownloadPathFollowing(filePath, false)
	return ok
}

// Reserve the reader and capture this upload generation atomically. A later
// upload must remain blocked until all readers have released the path.
func reserveDownloadPathFollowing(filePath string, allowLive bool) (*uploadPathState, bool) {
	cleanPath := path.Clean(filePath)
	if cleanPath == "." || cleanPath == "/" {
		return nil, false
	}
	transferPathReservationsMu.Lock()
	defer transferPathReservationsMu.Unlock()
	upload := activeUploadReservations[cleanPath]
	if upload != nil && !allowLive {
		return nil, false
	}
	activeDownloadPaths[cleanPath]++
	return upload, true
}

func releaseDownloadPath(filePath string) {
	cleanPath := path.Clean(filePath)
	if cleanPath == "." || cleanPath == "/" {
		return
	}
	transferPathReservationsMu.Lock()
	if count := activeDownloadPaths[cleanPath]; count <= 1 {
		delete(activeDownloadPaths, cleanPath)
	} else {
		activeDownloadPaths[cleanPath] = count - 1
	}
	transferPathReservationsMu.Unlock()
}

func downloadPathReserved(filePath string) bool {
	cleanPath := path.Clean(filePath)
	if cleanPath == "." || cleanPath == "/" {
		return false
	}
	transferPathReservationsMu.Lock()
	reserved := activeDownloadPaths[cleanPath] > 0
	transferPathReservationsMu.Unlock()
	return reserved
}

func listActiveSessions() []sessionSnapshot {
	var out []sessionSnapshot
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil {
			return true
		}
		snap := sessionSnapshot{
			ID:         s.ID,
			Remote:     s.remoteAddress,
			CurrentDir: s.CurrentDir,
			StartedAt:  s.StartedAt,
			LoggedIn:   s.IsLogged && !s.disconnected.Load(),
		}
		s.stateMu.RLock()
		snap.LastCommandAt = s.LastCommandAt
		snap.TransferDirection = s.TransferDirection
		snap.TransferPath = s.TransferPath
		snap.TransferBytes = s.TransferBytes.Load()
		snap.TransferStartedAt = s.TransferStartedAt
		snap.TransferSlaveName = s.TransferSlaveName
		snap.TransferSlaveIdx = s.TransferSlaveIdx
		s.stateMu.RUnlock()
		if snap.LoggedIn && s.User != nil {
			snap.User = s.User.Name
			snap.PrimaryGroup = s.User.PrimaryGroup
			snap.Flags = s.User.Flags
		}
		out = append(out, snap)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func ListActiveSessionsForPlugins() []plugin.ActiveSession {
	snaps := listActiveSessions()
	out := make([]plugin.ActiveSession, 0, len(snaps))
	for _, snap := range snaps {
		out = append(out, plugin.ActiveSession{
			ID:                snap.ID,
			User:              snap.User,
			PrimaryGroup:      snap.PrimaryGroup,
			Flags:             snap.Flags,
			Remote:            snap.Remote,
			CurrentDir:        snap.CurrentDir,
			StartedAt:         snap.StartedAt,
			LastCommandAt:     snap.LastCommandAt,
			LoggedIn:          snap.LoggedIn,
			TransferDirection: snap.TransferDirection,
			TransferPath:      snap.TransferPath,
			TransferBytes:     snap.TransferBytes,
			TransferStartedAt: snap.TransferStartedAt,
			TransferSlaveName: snap.TransferSlaveName,
			TransferSlaveIdx:  snap.TransferSlaveIdx,
		})
	}
	return out
}

func countTransfersForUser(username, direction string) int {
	username = strings.TrimSpace(username)
	direction = strings.ToLower(strings.TrimSpace(direction))
	if username == "" || direction == "" {
		return 0
	}
	count := 0
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil || !s.IsLogged || s.User == nil {
			return true
		}
		if !strings.EqualFold(s.User.Name, username) {
			return true
		}
		s.stateMu.RLock()
		matches := strings.EqualFold(s.TransferDirection, direction) && strings.TrimSpace(s.TransferPath) != ""
		s.stateMu.RUnlock()
		if matches {
			count++
		}
		return true
	})
	return count
}

func countSessionsForUser(username string) int {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0
	}
	count := 0
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil || s.disconnected.Load() || !s.IsLogged || s.User == nil {
			return true
		}
		if strings.EqualFold(s.User.Name, username) {
			count++
		}
		return true
	})
	return count
}

func countTransfersForUserAllDirections(username string) int {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0
	}
	count := 0
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil || !s.IsLogged || s.User == nil {
			return true
		}
		if !strings.EqualFold(s.User.Name, username) {
			return true
		}
		s.stateMu.RLock()
		hasTransfer := strings.TrimSpace(s.TransferPath) != "" && strings.TrimSpace(s.TransferDirection) != ""
		s.stateMu.RUnlock()
		if hasTransfer {
			count++
		}
		return true
	})
	return count
}

func countSessionsForGroup(group string) int {
	group = strings.TrimSpace(group)
	if group == "" {
		return 0
	}
	count := 0
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil || s.disconnected.Load() || !s.IsLogged || s.User == nil {
			return true
		}
		if s.User.IsInGroup(group) {
			count++
		}
		return true
	})
	return count
}

func DisconnectActiveSession(id uint64) bool {
	if id == 0 {
		return false
	}
	val, ok := activeSessions.Load(id)
	if !ok {
		return false
	}
	s, ok := val.(*Session)
	if !ok || s == nil || s.controlTransport == nil {
		return false
	}
	if s.disconnected.Swap(true) {
		return true
	}
	s.abortCurrentTransfer("session disconnected")
	_ = s.controlTransport.Close()
	return true
}

func kickActiveUser(username string) int {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0
	}
	kicked := 0
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil || !s.IsLogged || s.User == nil {
			return true
		}
		if strings.EqualFold(s.User.Name, username) {
			if s.disconnected.Swap(true) {
				return true
			}
			s.abortCurrentTransfer("user kicked")
			if s.controlTransport != nil {
				_ = s.controlTransport.Close()
			}
			kicked++
		}
		return true
	})
	return kicked
}

func UpdateActiveSessionACL(engine *acl.Engine) {
	if engine == nil {
		return
	}
	activeSessions.Range(func(key, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil {
			return true
		}
		s.ACLEngine = engine
		return true
	})
}

func remoteAddrString(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	defer func() {
		_ = recover()
	}()
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}
