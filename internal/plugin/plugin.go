// Package plugin defines the extensibility interface for weaveftpd.
//
// To write a plugin:
//
//  1. Create a new package under /plugins/<yourname>/
//  2. Implement the Plugin interface below
//  3. Register it in cmd/weaveftpd/main.go's plugin switch
//
// Plugins receive typed events via OnEvent. They have access to a Services
// handle (populated at Init) which exposes the master bridge, logger, and
// config. Plugins MUST NOT block in OnEvent — spawn a goroutine for any
// network I/O or long-running work.
//
// Example minimal plugin:
//
//	type MyPlugin struct{ svc *plugin.Services }
//	func New() *MyPlugin                                  { return &MyPlugin{} }
//	func (p *MyPlugin) Name() string                      { return "myplugin" }
//	func (p *MyPlugin) Init(s *plugin.Services, cfg map[string]interface{}) error {
//	    p.svc = s
//	    return nil
//	}
//	func (p *MyPlugin) OnEvent(evt *plugin.Event) error {
//	    if evt.Type == plugin.EventMKDir {
//	        go p.svc.Bridge.WriteFile(evt.Path+"/.mytag", []byte("hello"))
//	    }
//	    return nil
//	}
//	func (p *MyPlugin) Stop() error                       { return nil }
package plugin

import (
	"log"
	"time"

	"weaveftpd/internal/user"
)

// Event types dispatched by the PluginManager. Plugins should check evt.Type
// and ignore events they don't care about.
const (
	EventMKDir    = "MKDIR"    // New directory created
	EventRMDir    = "RMDIR"    // Directory removed
	EventUpload   = "UPLOAD"   // File uploaded successfully
	EventDownload = "DOWNLOAD" // File downloaded
	EventDelete   = "DELETE"   // File deleted
	EventRename   = "RENAME"   // File/dir renamed
	EventCWD      = "CWD"      // User changed directory
	EventLogin    = "LOGIN"    // User logged in
	EventLogout   = "LOGOUT"   // User logged out
	EventNuke     = "NUKE"     // Release nuked
	EventUnnuke   = "UNNUKE"   // Release unnuked
	EventComplete = "COMPLETE" // Race complete (all SFV files present)
)

// Event carries information about a single occurrence. Not every field is
// populated for every event — e.g. EventMKDir leaves Size/Speed zero.
type Event struct {
	Type     string                 // One of the Event* constants above
	User     *user.User             // Acting user (may be nil for system-originated events)
	Path     string                 // Full virtual path (directory for MKDIR, file for UPLOAD)
	Filename string                 // Base name of file/dir
	Size     int64                  // Bytes transferred (UPLOAD/DOWNLOAD)
	Speed    float64                // Bytes/sec (UPLOAD)
	Section  string                 // First path component, e.g. "TV-1080P"
	From     string                 // Source path for RENAME
	Extra    map[string]interface{} // Free-form for event-specific data
}

// Services is the handle plugins use to interact with weaveftpd. Populated by
// the PluginManager when it calls Init(). Plugins should store the pointer
// and use it in OnEvent callbacks.
type Services struct {
	Bridge               MasterBridge // VFS/slave access — WriteFile, ReadFile, PluginListDir, etc.
	Debug                bool         // Global debug flag
	Logger               *log.Logger  // Optional logger (may be nil — fall back to log.Printf)
	EmitEvent            func(eventType, path, filename, section string, size int64, speed float64, data map[string]string)
	ListSlaveStates      func() []SlaveState
	ListActiveSessions   func() []ActiveSession
	GetLiveTransferStats func() []LiveTransferStat
	DisconnectSession    func(id uint64) bool
	AbortTransfer        func(slaveName string, transferIndex int32, reason string) bool
	AbortSessionTransfer func(snapshot ActiveSession, reason string) bool
	ReleaseRoot          func(filePath string) string
}

type ActiveSession struct {
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

type LiveTransferStat struct {
	SlaveName     string
	TransferIndex int32
	Direction     string
	Path          string
	StartedAt     time.Time
	Transferred   int64
	SpeedBytes    float64
}

type SlaveState struct {
	Name            string
	Available       bool
	ReadOnly        bool
	ActiveTransfers int32
	FreeBytes       int64
	TotalBytes      int64
	Roots           []SlaveRootState
}

type SlaveRootState struct {
	Path       string
	MountPath  string
	FreeBytes  int64
	TotalBytes int64
}

type SiteContext interface {
	Reply(format string, args ...interface{})
	UserName() string
	UserFlags() string
	UserPrimaryGroup() string
	UserGroups() []string
}

type SiteCommandHandler interface {
	SiteCommands() []string
	HandleSiteCommand(ctx SiteContext, command string, args []string) bool
}

type MKDirValidator interface {
	ValidateMKDir(u *user.User, targetPath string) error
}

type LoginValidator interface {
	ValidateLogin(u *user.User, remoteIP string) error
}

type UploadValidator interface {
	ValidateUpload(u *user.User, targetPath string) error
}

type ConfigReloader interface {
	ReloadConfig(config map[string]interface{}) error
}

type RaceUser struct {
	Name    string
	Group   string
	Files   int
	Bytes   int64
	Speed   float64
	Percent int
}

type RaceGroup struct {
	Name    string
	Files   int
	Bytes   int64
	Speed   float64
	Percent int
}

type FileEntry struct {
	Name       string
	Size       int64
	IsDir      bool
	IsSymlink  bool
	LinkTarget string
	Mode       uint32
	ModTime    int64
	Owner      string
	Group      string
	Slave      string
}

type RequestRecord struct {
	Release string
	By      string
	Mode    string
	For     string
	Date    string
}

type RequestFillRecord struct {
	Release     string
	RequestedBy string
	FilledBy    string
	Date        string
}

// MasterBridge exposes the subset of the master's bridge that plugins need.
// This is a minimal surface — we can add methods as plugins require them.
type MasterBridge interface {
	PluginListDir(path string) []FileEntry
	MakeDir(path, owner, group string) error
	Symlink(linkPath, targetPath string) error
	VFSSymlink(linkPath, targetPath string) error
	Chmod(path string, mode uint32) error
	CreateSparseFile(path string, size int64, owner, group string) error
	DeleteFile(path string) error
	RenameFile(from, toDir, toName string) error
	RelocatePath(from, toDir, toName string) error
	RelocatePathToSlave(from, toDir, toName, targetSlave string) error
	ScrubReleaseRaceMetadata(dirPath, owner, group string) error
	WriteFile(path string, content []byte) error
	ReadFile(path string) ([]byte, error)
	ProbeMediaInfo(path, binary string, timeoutSeconds int) (map[string]string, error)
	CacheMediaInfo(path string, fields map[string]string)
	FileExists(path string) bool
	GetFileSize(path string) int64
	GetSFVData(dirPath string) map[string]uint32
	GetRequestData(dirPath string) ([]RequestRecord, []RequestFillRecord)
	SetRequestData(dirPath string, requests []RequestRecord, fills []RequestFillRecord)
	GetDirMediaInfo(dirPath string) map[string]string
	PluginGetVFSRaceStats(dirPath string) (users []RaceUser, groups []RaceGroup, totalBytes int64, present int, total int)
	PluginGetVFSReleaseStats(dirPath string) (users []RaceUser, groups []RaceGroup, totalBytes int64, present int, total int)
}

// Plugin is the interface every weaveftpd plugin must implement.
type Plugin interface {
	// Name returns a short, unique identifier (e.g. "tvmaze", "imdb").
	// Used as the key in the plugin config block.
	Name() string

	// Init is called once at startup after RegisterPlugin. The plugin receives
	// service handles and its own config sub-map from the YAML. It should
	// store the svc pointer for later use.
	Init(svc *Services, config map[string]interface{}) error

	// OnEvent is called synchronously for every dispatched event. It MUST
	// return quickly — spawn a goroutine for network I/O or heavy work.
	// Errors are logged but don't stop dispatch to other plugins.
	OnEvent(evt *Event) error

	// Stop is called at shutdown. Plugins should flush state and close any
	// background workers.
	Stop() error
}
