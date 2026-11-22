package slave

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"weaveftpd/internal/metrics"
	"weaveftpd/internal/protocol"
	"weaveftpd/internal/tlsutil"
)

const (
	socketTimeout             = 10 * time.Second
	actualTimeout             = 60 * time.Second
	diskStatusInterval        = 15 * time.Second
	minTransferBufferSize     = 1024 * 1024
	defaultTransferBufferSize = 4 * 1024 * 1024
	remergeEntryYieldEvery    = 128
)

// Slave is the slave daemon,
// It connects to a master, sends its name, then enters a command/response loop.
type Slave struct {
	name               string
	masterHost         string
	masterPort         int
	roots              []MountedRoot
	pasvPortMin        int
	pasvPortMax        int
	pasvNext           uint32
	tlsEnabled         bool
	tlsCert            string
	tlsKey             string
	tlsServerConfig    *tls.Config
	tlsServerConfigErr error
	masterCACert       string // CA used to verify the master's presented cert; empty = legacy InsecureSkipVerify
	clientCert         string // this slave's own mTLS identity presented to the master
	clientKey          string
	bindIP             string // public address advertised to data clients
	localBindIP        string // optional local interface used for listeners and outbound data sockets
	transferBufferSize int
	freeSpaceMB        int
	debug              bool

	conn            net.Conn
	stream          *protocol.ObjectStream
	writeMu         sync.Mutex // protects stream writes (gob is not thread-safe)
	transfers       sync.Map   // transferIndex (int32) -> *Transfer
	uploadByPath    sync.Map   // normalized virtual path -> *Transfer receiving that path
	nextTransferIdx int32

	online        atomic.Bool
	lastWriteTime atomic.Int64 // UnixMilli of last successful write
	timeout       time.Duration
	remergePaused atomic.Bool
	remergeActive atomic.Bool
	remergeAbort  atomic.Bool
}

// writeObject sends an object to the master with mutex protection.
// gob encoding is not thread-safe, so all writes must be serialized.
func (s *Slave) writeObject(obj interface{}) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	err := s.stream.WriteObject(obj)
	if err == nil {
		s.lastWriteTime.Store(time.Now().UnixMilli())
	}
	return err
}

func (s *Slave) writeObjectNoActivity(obj interface{}) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	err := s.stream.WriteObject(obj)
	if err == nil {
		s.lastWriteTime.Store(time.Now().UnixMilli())
	}
	return err
}

// writeStatusObject sends a best-effort progress update. It never blocks: if the
// shared write stream is busy (another transfer's update, a completion message,
// or remerge data is being written), the update is skipped instead of queued.
// Progress updates are advisory, so dropping one under load is harmless — and it
// keeps the transfer copy loop from stalling on writeMu contention while making
// sure transfer-complete messages (which fire the client's 226) aren't delayed
// behind a backlog of per-second status writes.
func (s *Slave) writeStatusObject(obj interface{}) {
	if !s.writeMu.TryLock() {
		metrics.StatusDrops.Inc()
		return
	}
	defer s.writeMu.Unlock()
	if err := s.stream.WriteObject(obj); err == nil {
		s.lastWriteTime.Store(time.Now().UnixMilli())
	}
}

// SlaveConfig holds slave configuration loaded from YAML
type SlaveConfig struct {
	Name               string        `yaml:"name"`
	MasterHost         string        `yaml:"master_host"`
	MasterPort         int           `yaml:"master_port"`
	Roots              []string      `yaml:"roots"` // e.g. ["/data/site", "/data2/site"]
	MountedRoots       []MountedRoot `yaml:"mounted_roots"`
	PasvPortMin        int           `yaml:"pasv_port_min"`
	PasvPortMax        int           `yaml:"pasv_port_max"`
	TLSEnabled         bool          `yaml:"tls_enabled"`
	TLSCert            string        `yaml:"tls_cert"`
	TLSKey             string        `yaml:"tls_key"`
	MasterCACert       string        `yaml:"master_ca_cert"` // CA cert used to verify the master's server cert
	ClientCert         string        `yaml:"client_cert"`    // this slave's mTLS client cert (CN must equal Name)
	ClientKey          string        `yaml:"client_key"`
	BindIP             string        `yaml:"bind_ip"`       // public PASV address; may be a NAT address
	LocalBindIP        string        `yaml:"local_bind_ip"` // local interface; empty lets the OS choose
	Timeout            int           `yaml:"timeout"`       // seconds, default 60
	TransferBufferSize int           `yaml:"transfer_buffer_size"`
	FreeSpaceMB        int           `yaml:"free_space_mb"`
	Debug              bool
}

type MountedRoot struct {
	Path      string `yaml:"path"`
	MountPath string `yaml:"mount_path"`
}

func NewSlave(cfg SlaveConfig) *Slave {
	timeout := actualTimeout
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}
	roots := normalizeMountedRoots(cfg.MountedRoots, cfg.Roots)
	if len(roots) == 0 {
		roots = []MountedRoot{{Path: "./site", MountPath: "/"}}
	}
	bufferSize := cfg.TransferBufferSize
	if bufferSize <= 0 {
		bufferSize = defaultTransferBufferSize
	}
	if bufferSize < minTransferBufferSize {
		bufferSize = minTransferBufferSize
	}
	tlsServerConfig, tlsServerConfigErr := loadTLSServerConfig(cfg.TLSCert, cfg.TLSKey)
	return &Slave{
		name:               cfg.Name,
		masterHost:         cfg.MasterHost,
		masterPort:         cfg.MasterPort,
		roots:              roots,
		pasvPortMin:        cfg.PasvPortMin,
		pasvPortMax:        cfg.PasvPortMax,
		tlsEnabled:         cfg.TLSEnabled,
		tlsCert:            cfg.TLSCert,
		tlsKey:             cfg.TLSKey,
		tlsServerConfig:    tlsServerConfig,
		tlsServerConfigErr: tlsServerConfigErr,
		masterCACert:       strings.TrimSpace(cfg.MasterCACert),
		clientCert:         strings.TrimSpace(cfg.ClientCert),
		clientKey:          strings.TrimSpace(cfg.ClientKey),
		bindIP:             strings.TrimSpace(cfg.BindIP),
		localBindIP:        strings.TrimSpace(cfg.LocalBindIP),
		timeout:            timeout,
		transferBufferSize: bufferSize,
		freeSpaceMB:        cfg.FreeSpaceMB,
		debug:              cfg.Debug,
	}
}

func loadTLSServerConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, DynamicRecordSizingDisabled: true}, nil
}

// buildMasterTLSConfig builds the TLS config used to dial the master's
// control port. When masterCACert is configured, the master's presented
// server certificate is verified against it (real verification, replacing
// the historical InsecureSkipVerify bypass); when clientCert/clientKey are
// also configured, this slave presents its own mTLS identity (CN must equal
// its registered slave name for the master's handshake check to pass).
func (s *Slave) buildMasterTLSConfig() (*tls.Config, error) {
	if (s.clientCert == "") != (s.clientKey == "") {
		return nil, fmt.Errorf("slave.client_cert and slave.client_key must be configured together")
	}

	tlsCfg := &tls.Config{
		ServerName: s.masterHost,
		MinVersion: tls.VersionTLS12,
	}

	if s.masterCACert != "" {
		pool, err := tlsutil.LoadCACertPool(s.masterCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load master_ca_cert: %w", err)
		}
		tlsCfg.RootCAs = pool
	} else {
		log.Printf("[Slave] WARNING: slave.master_ca_cert is not set - the control link is encrypted but the master's certificate is not verified. Configure mTLS for a verified master-slave link.")
		tlsCfg.InsecureSkipVerify = true
	}

	if s.clientCert != "" && s.clientKey != "" {
		cert, err := tls.LoadX509KeyPair(s.clientCert, s.clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client_cert/client_key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func normalizeMountedRoots(configured []MountedRoot, legacy []string) []MountedRoot {
	out := make([]MountedRoot, 0, len(configured)+len(legacy))
	for _, root := range configured {
		pathValue := strings.TrimSpace(root.Path)
		if pathValue == "" {
			continue
		}
		mountPath := cleanVirtualPath(root.MountPath)
		if mountPath == "" {
			mountPath = "/"
		}
		out = append(out, MountedRoot{
			Path:      filepath.Clean(pathValue),
			MountPath: mountPath,
		})
	}
	for _, root := range legacy {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		out = append(out, MountedRoot{
			Path:      filepath.Clean(root),
			MountPath: "/",
		})
	}
	return out
}

func cleanVirtualPath(p string) string {
	cleaned := path.Clean("/" + strings.TrimSpace(filepath.ToSlash(p)))
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	return cleaned
}

func mountPathMatches(mountPath, virtualPath string) bool {
	mountPath = cleanVirtualPath(mountPath)
	virtualPath = cleanVirtualPath(virtualPath)
	return mountPath == "/" || virtualPath == mountPath || strings.HasPrefix(virtualPath, mountPath+"/")
}

func stripMountPath(mountPath, virtualPath string) string {
	mountPath = cleanVirtualPath(mountPath)
	virtualPath = cleanVirtualPath(virtualPath)
	if mountPath == "/" {
		return strings.TrimPrefix(virtualPath, "/")
	}
	if virtualPath == mountPath {
		return ""
	}
	return strings.TrimPrefix(strings.TrimPrefix(virtualPath, mountPath), "/")
}

func (r MountedRoot) fullPath(virtualPath string) string {
	rel := stripMountPath(r.MountPath, virtualPath)
	if rel == "" {
		return r.Path
	}
	return filepath.Join(r.Path, filepath.FromSlash(rel))
}

func (r MountedRoot) virtualPath(fullPath string) (string, bool) {
	cleanRoot := filepath.Clean(r.Path)
	cleanFull := filepath.Clean(fullPath)
	rel, err := filepath.Rel(cleanRoot, cleanFull)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if rel == "." {
		return cleanVirtualPath(r.MountPath), true
	}
	return cleanVirtualPath(path.Join(r.MountPath, filepath.ToSlash(rel))), true
}

func (r MountedRoot) contains(fullPath string) bool {
	cleanRoot := filepath.Clean(r.Path)
	cleanFull := filepath.Clean(fullPath)
	if cleanFull == cleanRoot {
		return true
	}
	rel, err := filepath.Rel(cleanRoot, cleanFull)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func (s *Slave) rootsForVirtualPath(virtualPath string) []MountedRoot {
	virtualPath = cleanVirtualPath(virtualPath)
	matches := make([]MountedRoot, 0, len(s.roots))
	for _, root := range s.roots {
		if mountPathMatches(root.MountPath, virtualPath) {
			matches = append(matches, root)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return len(matches[i].MountPath) > len(matches[j].MountPath)
	})
	return matches
}

func (s *Slave) virtualSymlinkTarget(linkFullPath, rawTarget string) string {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return ""
	}
	physicalTarget := rawTarget
	if !filepath.IsAbs(physicalTarget) {
		physicalTarget = filepath.Join(filepath.Dir(linkFullPath), physicalTarget)
	}
	for _, root := range s.roots {
		if virtualTarget, ok := root.virtualPath(physicalTarget); ok {
			return virtualTarget
		}
	}
	return filepath.ToSlash(filepath.Clean(rawTarget))
}

type scanTarget struct {
	root                MountedRoot
	scanRoot            string
	virtualBase         string
	skipVirtualSubtrees []string
	pruneChildren       bool
}

func (s *Slave) scanTargetsForBase(basePath string, rootMode string) []scanTarget {
	basePath = cleanVirtualPath(basePath)
	rootMode = normalizeRemergeRootMode(rootMode)
	mountedPaths := s.nonRootMountPaths()
	hasDedicatedMountForBase := false
	if basePath != "/" && rootMode != "normal" {
		for _, mountPath := range mountedPaths {
			if mountPathMatches(mountPath, basePath) || strings.HasPrefix(mountPath, basePath+"/") {
				hasDedicatedMountForBase = true
				break
			}
		}
	}

	targets := make([]scanTarget, 0, len(s.roots))
	for _, root := range s.roots {
		mountPath := cleanVirtualPath(root.MountPath)
		if rootMode == "normal" && mountPath != "/" {
			continue
		}
		if rootMode == "mounted" && mountPath == "/" {
			continue
		}
		if mountPath == "/" && hasDedicatedMountForBase {
			continue
		}
		skipVirtualSubtrees := []string(nil)
		if mountPath == "/" {
			skipVirtualSubtrees = mountedPathsWithinBase(mountedPaths, basePath)
		}
		switch {
		case basePath == "/":
			targets = append(targets, scanTarget{root: root, scanRoot: root.Path, virtualBase: mountPath, skipVirtualSubtrees: skipVirtualSubtrees})
		case mountPathMatches(mountPath, basePath):
			targets = append(targets, scanTarget{root: root, scanRoot: root.fullPath(basePath), virtualBase: basePath, skipVirtualSubtrees: skipVirtualSubtrees})
		case strings.HasPrefix(mountPath, basePath+"/"):
			targets = append(targets, scanTarget{root: root, scanRoot: root.Path, virtualBase: mountPath, skipVirtualSubtrees: skipVirtualSubtrees})
		}
	}
	sort.SliceStable(targets, func(i, j int) bool {
		if basePath == "/" {
			if targets[i].root.MountPath == "/" && targets[j].root.MountPath != "/" {
				return true
			}
			if targets[j].root.MountPath == "/" && targets[i].root.MountPath != "/" {
				return false
			}
		}
		return len(targets[i].root.MountPath) > len(targets[j].root.MountPath)
	})
	return targets
}

func normalizeRemergeRootMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "normal", "site", "root", "roots", "true":
		return "normal"
	case "mounted", "mount", "mounts", "mounted_roots":
		return "mounted"
	case "all", "both", "false", "":
		return "all"
	default:
		return "all"
	}
}

func (s *Slave) nonRootMountPaths() []string {
	seen := make(map[string]struct{}, len(s.roots))
	out := make([]string, 0, len(s.roots))
	for _, root := range s.roots {
		mountPath := cleanVirtualPath(root.MountPath)
		if mountPath == "/" {
			continue
		}
		if _, ok := seen[mountPath]; ok {
			continue
		}
		seen[mountPath] = struct{}{}
		out = append(out, mountPath)
	}
	sort.Strings(out)
	return out
}

func mountedPathsWithinBase(mountPaths []string, basePath string) []string {
	basePath = cleanVirtualPath(basePath)
	out := make([]string, 0, len(mountPaths))
	for _, mountPath := range mountPaths {
		mountPath = cleanVirtualPath(mountPath)
		if basePath == "/" || mountPath == basePath || strings.HasPrefix(mountPath, basePath+"/") {
			out = append(out, mountPath)
		}
	}
	return out
}

func isSkippedRemergeSubtree(virtualPath string, skipVirtualSubtrees []string) bool {
	virtualPath = cleanVirtualPath(virtualPath)
	for _, skipPath := range skipVirtualSubtrees {
		skipPath = cleanVirtualPath(skipPath)
		if virtualPath == skipPath || strings.HasPrefix(virtualPath, skipPath+"/") {
			return true
		}
	}
	return false
}

func (s *Slave) physicalRoots() []string {
	out := make([]string, 0, len(s.roots))
	seen := make(map[string]struct{}, len(s.roots))
	for _, root := range s.roots {
		if _, ok := seen[root.Path]; ok {
			continue
		}
		seen[root.Path] = struct{}{}
		out = append(out, root.Path)
	}
	return out
}

func (s *Slave) getTransferBufferSize() int {
	if s == nil || s.transferBufferSize < minTransferBufferSize {
		return defaultTransferBufferSize
	}
	return s.transferBufferSize
}

func (s *Slave) serverTLSConfig() (*tls.Config, error) {
	if s == nil {
		return nil, fmt.Errorf("missing slave")
	}
	if s.tlsServerConfig != nil {
		return s.tlsServerConfig, nil
	}
	if s.tlsServerConfigErr != nil {
		return nil, s.tlsServerConfigErr
	}
	cfg, err := loadTLSServerConfig(s.tlsCert, s.tlsKey)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// Boot connects to master, performs handshake, sends disk status, then enters command loop.
// Boot connects to master with auto-reconnect.
func (s *Slave) Boot() error {
	for {
		err := s.connectAndRun()
		if err != nil {
			log.Printf("[Slave] Disconnected: %v", err)
		}
		s.online.Store(false)
		log.Printf("[Slave] Reconnecting to master in 10 seconds...")
		time.Sleep(10 * time.Second)
	}
}

// connectAndRun connects to master, registers, and enters command loop.
func (s *Slave) connectAndRun() error {
	log.Printf("[Slave] %s connecting to master at %s:%d", s.name, s.masterHost, s.masterPort)

	addr := net.JoinHostPort(s.masterHost, strconv.Itoa(s.masterPort))

	var conn net.Conn
	var err error

	if s.tlsEnabled {
		tlsCfg, cfgErr := s.buildMasterTLSConfig()
		if cfgErr != nil {
			return fmt.Errorf("failed to build master TLS config: %w", cfgErr)
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: socketTimeout}, "tcp", addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, socketTimeout)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to master: %w", err)
	}

	s.conn = conn
	s.stream = protocol.NewObjectStream(conn)
	log.Printf("[Slave] Connected to master")

	// Send slave name
	if err := s.writeObject(s.name); err != nil {
		s.conn.Close()
		return fmt.Errorf("failed to send slave name: %w", err)
	}

	// Send initial disk status
	ds := s.getDiskStatus()
	if err := s.writeObject(&protocol.AsyncResponseDiskStatus{Status: ds}); err != nil {
		s.conn.Close()
		return fmt.Errorf("failed to send disk status: %w", err)
	}

	s.online.Store(true)
	log.Printf("[Slave] Registered as '%s', entering command loop", s.name)

	stopDiskStatus := make(chan struct{})
	defer close(stopDiskStatus)
	go s.diskStatusLoop(stopDiskStatus)

	// Block on command loop
	return s.listenForCommands()
}

func (s *Slave) diskStatusLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(diskStatusInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !s.online.Load() {
				continue
			}
			if err := s.writeObjectNoActivity(&protocol.AsyncResponseDiskStatus{Status: s.getDiskStatus()}); err != nil {
				log.Printf("[Slave] Error sending periodic disk status: %v", err)
				s.shutdown()
				return
			}
		case <-stop:
			return
		}
	}
}

// listenForCommands reads AsyncCommand objects from master and dispatches them.
// ().
func (s *Slave) listenForCommands() error {
	lastActivity := time.Now()

	for s.online.Load() {
		// Set read deadline for socket timeout detection
		s.conn.SetReadDeadline(time.Now().Add(socketTimeout))

		obj, err := s.stream.ReadObject()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if we've exceeded actual timeout
				// But NOT during remerge — the master won't send commands
				// while we're flooding it with remerge data
				if time.Since(lastActivity) > s.timeout {
					// Check if any goroutine has been writing recently
					// (remerge writes keep the connection alive)
					if s.lastWriteTime.Load() > 0 {
						lastWrite := time.UnixMilli(s.lastWriteTime.Load())
						if time.Since(lastWrite) < s.timeout {
							// Writes are happening, connection is alive
							continue
						}
					}
					log.Printf("[Slave] No communication from master in %v, going offline", time.Since(lastActivity))
					s.shutdown()
					return fmt.Errorf("master timeout")
				}
				continue
			}
			log.Printf("[Slave] Error reading from master: %v", err)
			s.shutdown()
			return fmt.Errorf("lost connection to master: %w", err)
		}

		ac, ok := obj.(*protocol.AsyncCommand)
		if ac == nil || !ok {
			log.Printf("[Slave] Received unexpected object type: %T", obj)
			continue
		}

		lastActivity = time.Now()
		if s.debug {
			log.Printf("[Slave] Received command: %s", ac)
		}

		// Handle command in its own goroutine ( thread)
		go func(cmd *protocol.AsyncCommand) {
			resp := s.handleCommand(cmd)
			if resp != nil {
				if err := s.writeObject(resp); err != nil {
					log.Printf("[Slave] Error sending response for %s: %v", cmd.Name, err)
				}
			}
		}(ac)
	}

	return nil
}

// handleCommand dispatches a command to the appropriate handler.
//
//	-> BasicHandler.handleXxx
func (s *Slave) handleCommand(ac *protocol.AsyncCommand) interface{} {
	switch ac.Name {
	case "ping":
		return &protocol.AsyncResponse{Index: ac.Index}

	case "delete":
		return s.handleDelete(ac)

	case "rename":
		return s.handleRename(ac)
	case "relocate":
		return s.handleRelocate(ac)

	case "chmod":
		return s.handleChmod(ac)
	case "setModTime":
		return s.handleSetModTime(ac)

	case "symlink":
		return s.handleSymlink(ac)

	case "checksum":
		return s.handleChecksum(ac)

	case "listen":
		return s.handleListen(ac)

	case "connect":
		return s.handleConnect(ac)

	case "receive":
		return s.handleReceive(ac)

	case "send":
		return s.handleSend(ac)

	case "transferStats":
		return s.handleTransferStats(ac)

	case "runCommand":
		return s.handleRunCommand(ac)

	case "abort":
		return s.handleAbort(ac)

	case "remerge":
		return s.handleRemerge(ac)

	case "remergeStop":
		s.remergeAbort.Store(true)
		s.remergePaused.Store(false)
		return &protocol.AsyncResponse{Index: ac.Index}

	case "sfvFile":
		return s.handleSFVFile(ac)

	case "readFile":
		return s.handleReadFile(ac)

	case "readZipEntry":
		return s.handleReadZipEntry(ac)

	case "zipIntegrity":
		return s.handleZipIntegrity(ac)

	case "mediaProbe":
		return s.handleMediaInfo(ac)

	case "writeFile":
		return s.handleWriteFile(ac)

	case "createSparseFile":
		return s.handleCreateSparseFile(ac)

	case "makedir":
		return s.handleMakeDir(ac)

	case "remergePause":
		s.remergePaused.Store(true)
		return &protocol.AsyncResponse{Index: ac.Index}

	case "remergeResume":
		s.remergePaused.Store(false)
		return &protocol.AsyncResponse{Index: ac.Index}

	case "checkSSL":
		return &protocol.AsyncResponseSSLCheck{Index: ac.Index, SSLReady: s.tlsEnabled}

	case "maxpath":
		return &protocol.AsyncResponseMaxPath{Index: ac.Index, MaxPath: 4096}

	case "shutdown":
		log.Printf("[Slave] Master requested shutdown")
		s.shutdown()
		return nil

	default:
		log.Printf("[Slave] Unknown command: %s", ac.Name)
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "unknown command: " + ac.Name}
	}
}

// --- Command Handlers ---

func (s *Slave) handleDelete(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "delete: missing path"}
	}
	path := ac.Args[0]
	deletedAny := false

	for _, root := range s.rootsForVirtualPath(path) {
		fullPath := root.fullPath(path)
		if info, err := os.Stat(fullPath); err == nil {
			if info.IsDir() {
				if err := os.RemoveAll(fullPath); err != nil {
					return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("delete failed: %v", err)}
				}
			} else {
				if err := os.Remove(fullPath); err != nil {
					return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("delete failed: %v", err)}
				}
			}
			deletedAny = true
			// Clean up empty parent dirs ()
			s.cleanEmptyParents(fullPath, root.Path)
		}
	}
	if !deletedAny {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "delete failed: path not found on slave"}
	}

	// Report updated disk status
	ds := s.getDiskStatus()
	s.writeObject(&protocol.AsyncResponseDiskStatus{Status: ds})

	return &protocol.AsyncResponse{Index: ac.Index}
}

func (s *Slave) handleRename(ac *protocol.AsyncCommand) interface{} {
	// Args: [from, toDir, toName]
	if len(ac.Args) < 3 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "rename: need from, toDir, toName"}
	}
	from := ac.Args[0]
	toDir := ac.Args[1]
	toName := ac.Args[2]

	sourcePath, sourceRoot, err := s.getFileFromRootsWithRoot(from)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("rename failed: %v", err)}
	}
	destRoots := s.rootsForVirtualPath(toDir)
	if len(destRoots) == 0 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "rename failed: destination root not found"}
	}
	destRoot := destRoots[0]
	if destRoot.Path != sourceRoot.Path {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "rename failed: destination is on a different root; use relocate"}
	}
	toDirPath := destRoot.fullPath(toDir)
	toPath := filepath.Join(toDirPath, toName)
	if !destRoot.contains(toPath) {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "rename failed: destination escapes storage root"}
	}

	info, err := os.Stat(toDirPath)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("rename failed: destination directory not found: %v", err)}
	}
	if !info.IsDir() {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "rename failed: destination is not a directory"}
	}

	if err := os.Rename(sourcePath, toPath); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("rename failed: %v", err)}
	}

	return &protocol.AsyncResponse{Index: ac.Index}
}

func (s *Slave) handleRelocate(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 3 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "relocate: need from, toDir, toName"}
	}
	from := ac.Args[0]
	toDir := ac.Args[1]
	toName := ac.Args[2]

	sourcePath, sourceRoot, err := s.getFileFromRootsWithRoot(from)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("relocate: source not found: %v", err)}
	}
	if s.hasActiveTransferUnder(from) {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "relocate: source is busy with an active transfer"}
	}

	destRoot, err := s.selectRootForRelocate(sourceRoot, toDir)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("relocate: %v", err)}
	}
	destVirtualPath := filepath.ToSlash(path.Join(toDir, toName))
	if s.hasActiveTransferUnder(destVirtualPath) {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "relocate: destination is busy with an active transfer"}
	}

	toDirPath := destRoot.fullPath(toDir)
	toPath := filepath.Join(toDirPath, toName)
	if !destRoot.contains(toPath) {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "relocate failed: destination escapes storage root"}
	}
	if err := os.MkdirAll(toDirPath, 0755); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("relocate mkdir failed: %v", err)}
	}
	if _, err := os.Stat(toPath); err == nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "relocate failed: destination already exists"}
	}

	if destRoot.Path == sourceRoot.Path {
		if err := os.Rename(sourcePath, toPath); err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("relocate rename failed: %v", err)}
		}
	} else {
		if err := copyPath(sourcePath, toPath); err != nil {
			_ = os.RemoveAll(toPath)
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("relocate copy failed: %v", err)}
		}
		if err := os.RemoveAll(sourcePath); err != nil {
			_ = os.RemoveAll(toPath)
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("relocate cleanup failed: %v", err)}
		}
	}

	s.cleanEmptyParents(sourcePath, sourceRoot.Path)
	ds := s.getDiskStatus()
	s.writeObject(&protocol.AsyncResponseDiskStatus{Status: ds})
	return &protocol.AsyncResponse{Index: ac.Index}
}

func (s *Slave) handleChmod(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 2 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "chmod: need path and mode"}
	}
	mode64, err := strconv.ParseUint(ac.Args[1], 8, 32)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "chmod: invalid mode"}
	}
	changed := false
	for _, root := range s.rootsForVirtualPath(ac.Args[0]) {
		fullPath := root.fullPath(ac.Args[0])
		if _, err := os.Lstat(fullPath); err != nil {
			continue
		}
		if err := os.Chmod(fullPath, os.FileMode(mode64)); err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("chmod failed: %v", err)}
		}
		changed = true
	}
	if !changed {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "chmod: path not found"}
	}
	return &protocol.AsyncResponse{Index: ac.Index}
}

func (s *Slave) handleSymlink(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 2 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "symlink: need link and target"}
	}
	linkPath := ac.Args[0]
	targetPath := ac.Args[1]
	for _, root := range s.rootsForVirtualPath(targetPath) {
		fullLink := root.fullPath(linkPath)
		fullTarget := root.fullPath(targetPath)
		if _, err := os.Stat(fullTarget); err != nil {
			continue
		}
		if existingTarget, err := os.Readlink(fullLink); err == nil && cleanSymlinkTarget(existingTarget) == cleanSymlinkTarget(targetPath) {
			return &protocol.AsyncResponse{Index: ac.Index}
		}
		_ = os.Remove(fullLink)
		if err := os.Symlink(targetPath, fullLink); err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("symlink failed: %v", err)}
		}
		return &protocol.AsyncResponse{Index: ac.Index}
	}
	return &protocol.AsyncResponseError{Index: ac.Index, Message: "symlink: target not found"}
}

func cleanSymlinkTarget(target string) string {
	return filepath.ToSlash(filepath.Clean(strings.TrimSpace(target)))
}

// handleMakeDir physically creates empty directories on the slave disk.
func (s *Slave) handleMakeDir(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "makedir: missing path"}
	}
	dirPath := ac.Args[0]
	createOnAllRoots := len(ac.Args) > 1 && strings.EqualFold(strings.TrimSpace(ac.Args[1]), "all-roots")

	roots := s.rootsForVirtualPath(dirPath)
	if len(roots) == 0 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "no roots available"}
	}
	if createOnAllRoots {
		// keep matched roots
	} else {
		roots = roots[:1]
	}

	for _, root := range roots {
		fullPath := root.fullPath(dirPath)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			continue
		}
		if info, err := os.Lstat(fullPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("makedir failed: %v", err)}
		}
	}

	if s.debug {
		log.Printf("[Slave] Created directory %s", dirPath)
	}
	return &protocol.AsyncResponse{Index: ac.Index}
}

func (s *Slave) handleChecksum(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "checksum: missing path"}
	}
	path := ac.Args[0]

	for _, root := range s.rootsForVirtualPath(path) {
		fullPath := root.fullPath(path)
		f, err := os.Open(fullPath)
		if err != nil {
			continue
		}
		defer f.Close()

		h := crc32.NewIEEE()
		if _, err := io.Copy(h, f); err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("checksum error: %v", err)}
		}
		return &protocol.AsyncResponseChecksum{Index: ac.Index, Checksum: h.Sum32()}
	}

	return &protocol.AsyncResponseError{Index: ac.Index, Message: "file not found: " + path}
}

// handleListen - slave opens a passive port and waits for a connection.
func (s *Slave) handleListen(ac *protocol.AsyncCommand) interface{} {
	listener, err := s.listenOnPortRange()
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("listen failed: %v", err)}
	}

	encrypted, sslClientMode := parseListenFlags(ac.Args)

	idx := atomic.AddInt32(&s.nextTransferIdx, 1)
	t := NewTransfer(listener, nil, idx, s, encrypted, sslClientMode)
	s.transfers.Store(idx, t)
	time.AfterFunc(transferSetupReapGrace, func() { s.reapUnclaimedTransfer(idx) })

	port := listener.Addr().(*net.TCPAddr).Port

	return &protocol.AsyncResponseTransfer{
		Index: ac.Index,
		Info: protocol.ConnectInfo{
			Port:          port,
			TransferIndex: idx,
			Status:        t.currentStatus(false, ""),
		},
	}
}

func parseListenFlags(args []string) (encrypted bool, sslClientMode bool) {
	if len(args) == 0 {
		return false, false
	}
	parts := strings.SplitN(args[0], ":", 2)
	encrypted, _ = strconv.ParseBool(parts[0])
	if len(parts) > 1 {
		sslClientMode, _ = strconv.ParseBool(parts[1])
	}
	return encrypted, sslClientMode
}

// handleConnect - slave connects out to a given address (active mode).
func (s *Slave) handleConnect(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "connect: missing address"}
	}
	address := ac.Args[0]

	idx := atomic.AddInt32(&s.nextTransferIdx, 1)
	port := 0
	if _, portStr, splitErr := net.SplitHostPort(address); splitErr == nil {
		if parsedPort, convErr := strconv.Atoi(portStr); convErr == nil {
			port = parsedPort
		}
	}
	t := NewTransfer(nil, nil, idx, s, len(ac.Args) > 1 && ac.Args[1] == "true", len(ac.Args) > 2 && ac.Args[2] == "true")
	t.SetActiveAddress(address)
	s.transfers.Store(idx, t)
	time.AfterFunc(transferSetupReapGrace, func() { s.reapUnclaimedTransfer(idx) })

	return &protocol.AsyncResponseTransfer{
		Index: ac.Index,
		Info: protocol.ConnectInfo{
			Port:          port,
			TransferIndex: idx,
			Status:        t.currentStatus(false, ""),
		},
	}
}

// handleReceive - slave receives (uploads) a file from the FTP client via the data connection.
//
// Args: [type, position, transferIndex, inetAddress, path]
func (s *Slave) handleReceive(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 5 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "receive: not enough args"}
	}

	var transferIdx int32
	var position int64
	var transferType byte = 'I'
	if len(ac.Args) > 0 && strings.TrimSpace(ac.Args[0]) != "" {
		transferType = strings.ToUpper(strings.TrimSpace(ac.Args[0]))[0]
	}
	fmt.Sscanf(ac.Args[1], "%d", &position)
	fmt.Sscanf(ac.Args[2], "%d", &transferIdx)
	expectedPeer := ac.Args[3]
	path := ac.Args[4]

	val, ok := s.transfers.Load(transferIdx)
	if !ok {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "transfer not found"}
	}
	t := val.(*Transfer)
	t.SetPath(path)
	t.SetTransferMode(transferType)

	// Acknowledge to master that we're starting (: sendResponse(new AsyncResponse(ac.getIndex())))
	// Publish the pending receiver before ACK makes the file visible on master.
	s.registerUpload(t)
	s.writeObject(&protocol.AsyncResponse{Index: ac.Index})

	// Actually receive the file - this blocks until done
	status := t.ReceiveFile(path, position, expectedPeer)
	return &protocol.AsyncResponseTransferStatus{Status: status}
}

// handleSend - slave sends (downloads) a file to the FTP client via the data connection.
//
// Args: [type, position, transferIndex, inetAddress, path]
func (s *Slave) handleSend(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 5 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "send: not enough args"}
	}

	var transferIdx int32
	var position int64
	var transferType byte = 'I'
	if len(ac.Args) > 0 && strings.TrimSpace(ac.Args[0]) != "" {
		transferType = strings.ToUpper(strings.TrimSpace(ac.Args[0]))[0]
	}
	fmt.Sscanf(ac.Args[1], "%d", &position)
	fmt.Sscanf(ac.Args[2], "%d", &transferIdx)
	expectedPeer := ac.Args[3]
	path := ac.Args[4]

	val, ok := s.transfers.Load(transferIdx)
	if !ok {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "transfer not found"}
	}
	t := val.(*Transfer)
	t.SetPath(path)
	t.SetTransferMode(transferType)

	// Acknowledge to master
	s.writeObject(&protocol.AsyncResponse{Index: ac.Index})

	// Actually send the file
	status := t.SendFile(path, position, expectedPeer)
	return &protocol.AsyncResponseTransferStatus{Status: status}
}

func (s *Slave) handleAbort(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return nil
	}
	var transferIdx int32
	fmt.Sscanf(ac.Args[0], "%d", &transferIdx)

	reason := "aborted by master"
	if len(ac.Args) > 1 {
		reason = ac.Args[1]
	}

	if val, ok := s.transfers.Load(transferIdx); ok {
		t := val.(*Transfer)
		t.Abort(reason)
		// If the transfer was never claimed by a receive/send, no defer will ever
		// remove it from the map; drop it here so an aborted setup can't leak.
		if !t.claimed.Load() {
			s.removeTransfer(transferIdx)
		}
	}

	return &protocol.AsyncResponse{Index: ac.Index}
}

// reapUnclaimedTransfer drops a LISTEN/CONNECT transfer that was set up but never
// claimed by a receive/send within the grace window (so no defer will ever clean
// it). Without this the slave's transfers map grows for the daemon's whole uptime
// and the per-CWD race-stats scan over it gets progressively slower.
func (s *Slave) reapUnclaimedTransfer(idx int32) {
	val, ok := s.transfers.Load(idx)
	if !ok {
		return
	}
	t, ok := val.(*Transfer)
	if !ok || t == nil || t.claimed.Load() {
		return
	}
	t.Abort("setup timeout: transfer never started")
	s.removeTransfer(idx)
}

func (s *Slave) handleTransferStats(ac *protocol.AsyncCommand) interface{} {
	stats := make([]protocol.TransferLiveStat, 0)
	s.transfers.Range(func(_, value interface{}) bool {
		t, ok := value.(*Transfer)
		if !ok || t == nil {
			return true
		}
		stat := t.SnapshotLiveStat()
		if stat.Direction == TransferUnknown {
			return true
		}
		stats = append(stats, stat)
		return true
	})
	return &protocol.AsyncResponseTransferStats{Index: ac.Index, Stats: stats}
}

func (s *Slave) handleRunCommand(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 5 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "runCommand: not enough args"}
	}

	command := strings.TrimSpace(ac.Args[0])
	if command == "" {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "runCommand: empty command"}
	}

	timeoutSeconds, _ := strconv.Atoi(strings.TrimSpace(ac.Args[1]))
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	var args []string
	if err := json.Unmarshal([]byte(ac.Args[2]), &args); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("runCommand args decode failed: %v", err)}
	}

	env := map[string]string{}
	if err := json.Unmarshal([]byte(ac.Args[3]), &env); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("runCommand env decode failed: %v", err)}
	}

	dirPath := strings.TrimSpace(ac.Args[4])
	localPath := s.resolveLocalPath(dirPath)
	env["WEAVEFTPD_HOOK_TARGET"] = "slave"
	env["WEAVEFTPD_SLAVE_NAME"] = s.name
	if localPath != "" {
		env["WEAVEFTPD_LOCAL_PATH"] = localPath
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), flattenEnvMap(env)...)
	if localPath != "" {
		cmd.Dir = localPath
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := err.Error()
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			msg = msg + ": " + trimmed
		}
		return &protocol.AsyncResponseError{Index: ac.Index, Message: msg}
	}
	return &protocol.AsyncResponseCommandResult{Index: ac.Index, Output: strings.TrimSpace(string(out))}
}

func (s *Slave) resolveLocalPath(dirPath string) string {
	cleaned := strings.TrimLeft(filepath.Clean(dirPath), `/\`)
	for _, root := range s.rootsForVirtualPath(dirPath) {
		candidate := root.fullPath(cleaned)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	roots := s.rootsForVirtualPath(dirPath)
	if len(roots) == 0 {
		return ""
	}
	return roots[0].fullPath(cleaned)
}

func flattenEnvMap(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// handleRemerge - slave scans its roots and sends all files to master.
func (s *Slave) handleRemerge(ac *protocol.AsyncCommand) interface{} {
	if !s.remergeActive.CompareAndSwap(false, true) {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "remerge already running on slave"}
	}
	s.remergeAbort.Store(false)
	defer func() {
		s.remergeAbort.Store(false)
		s.remergeActive.Store(false)
	}()

	basePath := "/"
	if len(ac.Args) > 0 {
		basePath = ac.Args[0]
	}
	rootMode := "all"
	if len(ac.Args) > 2 {
		rootMode = normalizeRemergeRootMode(ac.Args[2])
	}
	remergeDelay := time.Duration(0)
	remergePauseOnActiveTransfers := 0
	excludePathsStart := 3
	if len(ac.Args) > 4 {
		if delayMS, err := strconv.Atoi(strings.TrimSpace(ac.Args[3])); err == nil {
			if pauseOnActive, err := strconv.Atoi(strings.TrimSpace(ac.Args[4])); err == nil {
				if delayMS > 0 {
					remergeDelay = time.Duration(delayMS) * time.Millisecond
				}
				if pauseOnActive > 0 {
					remergePauseOnActiveTransfers = pauseOnActive
				}
				excludePathsStart = 5
			}
		}
	}
	excludePaths := normalizeExcludeVFSPaths(ac.Args[excludePathsStart:])

	scanTargets := s.scanTargetsForBase(basePath, rootMode)
	for i := range scanTargets {
		scanTargets[i].pruneChildren = len(scanTargets) == 1
	}
	opts := remergeScanOptions{delay: remergeDelay, pauseOnActiveTransfers: remergePauseOnActiveTransfers}
	log.Printf("[Slave] Starting remerge from %s across %d roots (roots=%s delay=%s pause_on_active_transfers=%d)",
		basePath, len(scanTargets), rootMode, opts.delay, opts.pauseOnActiveTransfers)

	totalFiles := 0
	totalDirs := 0
	sentDirs := 0

	var scanErr error
	for _, target := range scanTargets {
		scanRoot := target.scanRoot

		// Check if scanRoot exists
		if _, err := os.Stat(scanRoot); err != nil {
			log.Printf("[Slave] Remerge: root %s does not exist, skipping", scanRoot)
			continue
		}

		log.Printf("[Slave] Remerge: scanning root %s", scanRoot)

		counts := remergeScanCounts{}
		if err := s.scanRemergeDirectory(target, scanRoot, excludePaths, opts, &counts); err != nil {
			if s.remergeAbort.Load() {
				log.Printf("[Slave] Remerge root %s stopped: abort requested", target.root.Path)
				return &protocol.AsyncResponseError{Index: ac.Index, Message: "remerge stopped"}
			}
			log.Printf("[Slave] Remerge root %s stopped: %v", target.root.Path, err)
			scanErr = err
		}
		totalFiles += counts.totalFiles
		totalDirs += counts.totalDirs
		sentDirs += counts.sentDirs

		log.Printf("[Slave] Remerge root %s done: sent %d directories", target.root.Path, sentDirs)
	}

	log.Printf("[Slave] Remerge complete: %d files, %d dirs across %d sent directories", totalFiles, totalDirs, sentDirs)
	if scanErr != nil {
		// A root failed to scan completely (I/O error, went offline mid-walk).
		// Report incomplete so the master keeps the directory snapshots we did
		// send but SKIPS the final PurgeUnseen — otherwise files under the
		// unscanned area would be wrongly removed from the index.
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("remerge incomplete: %v", scanErr)}
	}
	return &protocol.AsyncResponse{Index: ac.Index}
}

type remergeScanCounts struct {
	totalFiles int
	totalDirs  int
	sentDirs   int
}

type remergeScanOptions struct {
	delay                  time.Duration
	pauseOnActiveTransfers int
}

func (s *Slave) scanRemergeDirectory(target scanTarget, dir string, excludePaths []string, opts remergeScanOptions, counts *remergeScanCounts) error {
	if !s.waitForRemergeSlot(opts) {
		if s.remergeAbort.Load() {
			return fmt.Errorf("remerge stopped")
		}
		return fmt.Errorf("slave went offline")
	}

	virtualDir, ok := target.root.virtualPath(dir)
	if !ok {
		return nil
	}
	if dir != target.scanRoot && isExcludedVFSPath(virtualDir, excludePaths) {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	dirModTime := time.Now().Unix()
	if info, err := os.Stat(dir); err == nil {
		dirModTime = info.ModTime().Unix()
	}

	files := make([]protocol.LightRemoteInode, 0, len(entries))
	childDirs := make([]string, 0)
	for i, entry := range entries {
		if !s.waitForRemergeSlot(opts) {
			if s.remergeAbort.Load() {
				return fmt.Errorf("remerge stopped")
			}
			return fmt.Errorf("slave went offline")
		}
		fullPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		childVirtualPath, ok := target.root.virtualPath(fullPath)
		if !ok || isExcludedVFSPath(childVirtualPath, excludePaths) || isSkippedRemergeSubtree(childVirtualPath, target.skipVirtualSubtrees) {
			continue
		}
		inode := protocol.LightRemoteInode{
			Name:         info.Name(),
			IsDir:        info.IsDir(),
			IsSymlink:    info.Mode()&os.ModeSymlink != 0,
			Size:         info.Size(),
			LastModified: info.ModTime().Unix(),
			Owner:        defaultFileOwner,
			Group:        defaultFileGroup,
		}
		if inode.IsSymlink {
			if linkTarget, err := os.Readlink(fullPath); err == nil {
				inode.LinkTarget = s.virtualSymlinkTarget(fullPath, linkTarget)
			}
		}
		files = append(files, inode)

		if info.IsDir() {
			counts.totalDirs++
			childDirs = append(childDirs, fullPath)
		} else {
			counts.totalFiles++
		}
		if opts.delay > 0 && (i+1)%remergeEntryYieldEvery == 0 {
			time.Sleep(opts.delay)
		}
	}

	resp := &protocol.AsyncResponseRemerge{
		Path:            virtualDir,
		Files:           files,
		LastModified:    dirModTime,
		SkippedSubtrees: target.skipVirtualSubtrees,
		PruneChildren:   target.pruneChildren,
	}
	if err := s.writeObject(resp); err != nil {
		return fmt.Errorf("send remerge for %s: %w", virtualDir, err)
	}
	counts.sentDirs++
	if opts.delay > 0 {
		time.Sleep(opts.delay)
	}

	for _, childDir := range childDirs {
		if err := s.scanRemergeDirectory(target, childDir, excludePaths, opts, counts); err != nil {
			return err
		}
	}
	return nil
}

func (s *Slave) waitForRemergeSlot(opts remergeScanOptions) bool {
	for s.online.Load() {
		if s.remergeAbort.Load() {
			return false
		}
		if s.remergePaused.Load() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if opts.pauseOnActiveTransfers > 0 && s.activeTransferCount() >= opts.pauseOnActiveTransfers {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return true
	}
	return false
}

func (s *Slave) activeTransferCount() int {
	count := 0
	s.transfers.Range(func(_, value interface{}) bool {
		t, ok := value.(*Transfer)
		if !ok || t == nil {
			return true
		}
		stat := t.SnapshotLiveStat()
		if stat.Direction != TransferUnknown {
			count++
		}
		return true
	})
	return count
}

func normalizeExcludeVFSPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = path.Clean("/" + strings.TrimSpace(filepath.ToSlash(p)))
		if p == "/" || p == "." || p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func isExcludedVFSPath(p string, excluded []string) bool {
	if strings.TrimSpace(p) != p || !strings.HasPrefix(p, "/") || strings.Contains(p, "\\") ||
		strings.Contains(p, "//") || strings.Contains(p, "/./") || strings.Contains(p, "/../") ||
		strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") {
		p = path.Clean("/" + strings.TrimSpace(filepath.ToSlash(p)))
	}
	if p == "/" || p == "." || p == "" {
		return false
	}
	for _, root := range excluded {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

// handleSFVFile - slave parses an SFV file and sends the entries to master.
func (s *Slave) handleSFVFile(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "sfvFile: missing path"}
	}
	sfvPath := ac.Args[0]

	for _, root := range s.rootsForVirtualPath(sfvPath) {
		fullPath := root.fullPath(sfvPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		// Parse SFV lines as "filename<ws>HEXCRC32", allowing spaces or tabs
		// before the checksum while preserving filenames exactly.
		var entries []protocol.SFVEntry
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			entry, ok := parseSFVEntryLine(line)
			if !ok {
				continue
			}
			entries = append(entries, entry)
		}

		// Calculate CRC32 of the SFV file itself
		h := crc32.NewIEEE()
		h.Write(data)

		if s.debug {
			log.Printf("[Slave] Parsed SFV %s: %d entries", sfvPath, len(entries))
		}
		return &protocol.AsyncResponseSFVInfo{
			Index:    ac.Index,
			SFVName:  filepath.Base(sfvPath),
			Entries:  entries,
			Checksum: h.Sum32(),
			Size:     int64(len(data)),
		}
	}

	return &protocol.AsyncResponseError{Index: ac.Index, Message: "SFV not found: " + sfvPath}
}

func parseSFVEntryLine(line string) (protocol.SFVEntry, bool) {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimPrefix(line, "\ufeff")
	if strings.TrimSpace(line) == "" {
		return protocol.SFVEntry{}, false
	}
	if strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), ";") {
		return protocol.SFVEntry{}, false
	}
	if len(line) < 9 {
		return protocol.SFVEntry{}, false
	}

	end := len(line)
	for end > 0 && unicode.IsSpace(rune(line[end-1])) {
		end--
	}
	if end < 8 {
		return protocol.SFVEntry{}, false
	}

	crcStr := line[end-8 : end]
	crc, err := strconv.ParseUint(crcStr, 16, 32)
	if err != nil {
		return protocol.SFVEntry{}, false
	}

	sep := end - 8
	if sep <= 0 || !unicode.IsSpace(rune(line[sep-1])) {
		return protocol.SFVEntry{}, false
	}
	for sep > 0 && unicode.IsSpace(rune(line[sep-1])) {
		sep--
	}
	fileName := strings.TrimSpace(line[:sep])
	fileName = strings.TrimPrefix(fileName, "\ufeff")
	if fileName == "" {
		return protocol.SFVEntry{}, false
	}

	return protocol.SFVEntry{
		FileName: fileName,
		CRC32:    uint32(crc),
	}, true
}

// handleReadFile - slave reads a small file and sends content to master.
// Used for .message, .imdb, .nfo display without a full transfer setup.
func (s *Slave) handleReadFile(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "readFile: missing path"}
	}
	filePath := ac.Args[0]

	for _, root := range s.rootsForVirtualPath(filePath) {
		fullPath := root.fullPath(filePath)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		// Safety: don't read files larger than 64KB
		if info.Size() > 65536 {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: "file too large for readFile"}
		}
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("read error: %v", err)}
		}
		return &protocol.AsyncResponseFileContent{
			Index:   ac.Index,
			Content: data,
		}
	}

	return &protocol.AsyncResponseError{Index: ac.Index, Message: "file not found: " + filePath}
}

func (s *Slave) handleReadZipEntry(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 2 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "readZipEntry: missing archive path or entry name"}
	}
	archivePath := ac.Args[0]
	entryName := strings.TrimSpace(ac.Args[1])
	if entryName == "" {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "readZipEntry: empty entry name"}
	}

	for _, root := range s.rootsForVirtualPath(archivePath) {
		fullPath := root.fullPath(archivePath)
		info, err := os.Stat(fullPath)
		if err != nil || info.IsDir() {
			continue
		}
		zr, err := zip.OpenReader(fullPath)
		if err != nil {
			return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("zip open failed: %v", err)}
		}
		defer zr.Close()
		for _, f := range zr.File {
			base := path.Base(strings.ReplaceAll(f.Name, "\\", "/"))
			if !strings.EqualFold(base, entryName) || f.FileInfo().IsDir() {
				continue
			}
			if f.UncompressedSize64 > 65536 {
				return &protocol.AsyncResponseError{Index: ac.Index, Message: "zip entry too large for readZipEntry"}
			}
			rc, err := f.Open()
			if err != nil {
				return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("zip entry open failed: %v", err)}
			}
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("zip entry read failed: %v", err)}
			}
			return &protocol.AsyncResponseZipEntryContent{
				Index:     ac.Index,
				EntryName: f.Name,
				Content:   data,
			}
		}
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("zip entry not found: %s", entryName)}
	}

	return &protocol.AsyncResponseError{Index: ac.Index, Message: "file not found: " + archivePath}
}

func (s *Slave) handleZipIntegrity(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "zipIntegrity: missing archive path"}
	}
	archivePath := ac.Args[0]

	for _, root := range s.rootsForVirtualPath(archivePath) {
		fullPath := root.fullPath(archivePath)
		info, err := os.Stat(fullPath)
		if err != nil || info.IsDir() {
			continue
		}
		ok, err := validateZipIntegrity(fullPath)
		if err != nil {
			// The file exists (stat above), so a read/open error here means the
			// archive itself is corrupt or truncated. Report it as a failed
			// integrity check (OK=false) so the master deletes it. Returning an
			// error instead made the master treat a broken zip as "check could not
			// run" and keep it, which let truncated volumes count toward complete.
			log.Printf("[Slave] zip integrity check failed for %s: %v", archivePath, err)
			return &protocol.AsyncResponseZipIntegrity{Index: ac.Index, OK: false}
		}
		return &protocol.AsyncResponseZipIntegrity{Index: ac.Index, OK: ok}
	}

	return &protocol.AsyncResponseError{Index: ac.Index, Message: "file not found: " + archivePath}
}

func validateZipIntegrity(fullPath string) (bool, error) {
	zr, err := zip.OpenReader(fullPath)
	if err != nil {
		return false, err
	}
	defer zr.Close()

	files := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		files++
		rc, err := f.Open()
		if err != nil {
			return false, err
		}
		_, copyErr := io.Copy(io.Discard, rc)
		closeErr := rc.Close()
		if copyErr != nil {
			return false, copyErr
		}
		if closeErr != nil {
			return false, closeErr
		}
	}
	if files == 0 {
		return false, fmt.Errorf("zip file empty")
	}
	return true, nil
}

func (s *Slave) handleMediaInfo(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "media probe: missing path"}
	}
	filePath := ac.Args[0]

	for _, root := range s.rootsForVirtualPath(filePath) {
		fullPath := root.fullPath(filePath)
		info, err := os.Stat(fullPath)
		if err != nil || info.IsDir() {
			continue
		}
		if fields, handled, probeErr := probeFastAudioMetadata(fullPath); handled && probeErr == nil {
			deriveMediaInfoFields(fields)
			return &protocol.AsyncResponseMediaInfo{Index: ac.Index, Fields: fields}
		}
		if fields, handled, probeErr := probeFastVideoMetadata(fullPath); handled && probeErr == nil {
			deriveMediaInfoFields(fields)
			return &protocol.AsyncResponseMediaInfo{Index: ac.Index, Fields: fields}
		}
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "media probe unsupported for file type: " + filepath.Ext(fullPath)}
	}
	return &protocol.AsyncResponseError{Index: ac.Index, Message: "file not found: " + filePath}
}

func deriveMediaInfoFields(f map[string]string) {
	copyFirst := func(dst string, srcs ...string) {
		if f[dst] != "" {
			return
		}
		for _, src := range srcs {
			if val := f[src]; val != "" {
				f[dst] = val
				return
			}
		}
	}
	copyFirst("title", "g_title", "g_album", "g_completename", "g_complete_name")
	copyFirst("genre", "g_genre")
	copyFirst("year", "g_recordeddate", "g_recorded_date", "g_originalreleaseddate", "g_original_released_date", "g_encodeddate", "g_encoded_date")
	copyFirst("format", "g_format")
	copyFirst("audio_format", "a_format", "a_commercialname", "a_commercial_name")
	copyFirst("bitrate", "a_bitrate_string", "a_bitrate", "a_bit_rate", "g_overallbitrate_string", "g_overallbitrate", "g_overall_bit_rate")
	copyFirst("bitrate_mode", "a_bitrate_mode", "a_bitratemode", "a_bit_rate_mode", "g_overallbitrate_mode", "g_overall_bit_rate_mode")
	copyFirst("sample_rate", "a_samplingrate_string", "a_samplingrate", "a_sampling_rate")
	copyFirst("channels", "a_channels_string", "a_channel_s_string", "a_channels", "a_channel_s_")
	copyFirst("video_format", "v_format", "v_commercialname", "v_commercial_name")
	copyFirst("width", "v_width")
	copyFirst("height", "v_height")
	copyFirst("frame_rate", "v_framerate", "v_frame_rate")
	copyFirst("duration", "g_duration", "v_duration", "a_duration")
	copyFirst("subtitle_format", "s_format", "s_commercialname", "s_commercial_name")
	f["year"] = normalizeMediaYear(f["year"])
	f["bitrate"] = normalizeMediaBitrate(f["bitrate"])
	f["sample_rate"] = normalizeMediaSampleRate(f["sample_rate"])
	f["channels"] = normalizeMediaChannels(f["channels"])
	f["duration"] = normalizeMediaDuration(f["duration"])
}

func normalizeMediaYear(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 4 {
		year := s[:4]
		if _, err := strconv.Atoi(year); err == nil {
			return year
		}
	}
	return s
}

func normalizeMediaBitrate(s string) string {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return raw
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "kb") || strings.Contains(lower, "mb") {
		return raw
	}
	digits := strings.NewReplacer(" ", "", ",", "", ".", "").Replace(raw)
	if n, err := strconv.Atoi(digits); err == nil && n > 0 {
		if n >= 1000 {
			return fmt.Sprintf("%dkbps", n/1000)
		}
		return fmt.Sprintf("%dbps", n)
	}
	return raw
}

func normalizeMediaSampleRate(s string) string {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return raw
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "hz") {
		return strings.TrimSuffix(strings.TrimSuffix(lower, " hz"), "hz")
	}
	return raw
}

func normalizeMediaChannels(s string) string {
	raw := strings.TrimSpace(s)
	switch raw {
	case "1":
		return "Mono"
	case "2":
		return "Stereo"
	case "6":
		return "5.1"
	case "8":
		return "7.1"
	default:
		return raw
	}
}

func normalizeMediaDuration(s string) string {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return raw
	}
	if strings.Contains(strings.ToLower(raw), "min") || strings.Contains(raw, ":") {
		return raw
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds > 0 {
		min := int(seconds) / 60
		sec := int(seconds) % 60
		if min > 0 {
			return fmt.Sprintf("%dm%02ds", min, sec)
		}
		return fmt.Sprintf("%ds", sec)
	}
	return raw
}

// handleWriteFile - master writes a small file to slave (e.g. .message).
func (s *Slave) handleWriteFile(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 1 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "writeFile: missing path"}
	}
	filePath := ac.Args[0]

	// Content is in Args[1] (base64 would be safer but for small text files this works)
	var content []byte
	if len(ac.Args) > 1 {
		content = []byte(ac.Args[1])
	}

	// Write to first root
	fullPath, err := s.getDirForUpload(filePath)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "no roots"}
	}
	os.MkdirAll(filepath.Dir(fullPath), 0755)

	if err := os.WriteFile(fullPath, content, 0644); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("write error: %v", err)}
	}

	log.Printf("[Slave] Wrote file %s (%d bytes)", filePath, len(content))
	return &protocol.AsyncResponse{Index: ac.Index}
}

func (s *Slave) handleCreateSparseFile(ac *protocol.AsyncCommand) interface{} {
	if len(ac.Args) < 2 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "createSparseFile: missing path or size"}
	}
	filePath := ac.Args[0]
	size, err := strconv.ParseInt(strings.TrimSpace(ac.Args[1]), 10, 64)
	if err != nil || size < 0 {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "createSparseFile: invalid size"}
	}
	fullPath, err := s.getDirForUpload(filePath)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "no roots"}
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("mkdir error: %v", err)}
	}
	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("create error: %v", err)}
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("truncate error: %v", err)}
	}
	if err := f.Close(); err != nil {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: fmt.Sprintf("close error: %v", err)}
	}

	ds := s.getDiskStatus()
	s.writeObject(&protocol.AsyncResponseDiskStatus{Status: ds})
	log.Printf("[Slave] Created sparse file %s (%d bytes)", filePath, size)
	return &protocol.AsyncResponse{Index: ac.Index}
}

// --- Utility methods ---

func (s *Slave) getDiskStatus() protocol.DiskStatus {
	var totalAvail, totalCap int64
	roots := make([]protocol.RootDiskStatus, 0, len(s.roots))
	seen := make(map[string]struct{}, len(s.roots))
	for _, root := range s.roots {
		key := root.Path + "|" + cleanVirtualPath(root.MountPath)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		avail, cap := getDiskSpace(root.Path)
		totalAvail += avail
		totalCap += cap
		roots = append(roots, protocol.RootDiskStatus{
			Path:           root.Path,
			MountPath:      cleanVirtualPath(root.MountPath),
			SpaceAvailable: avail,
			SpaceCapacity:  cap,
		})
	}
	return protocol.DiskStatus{
		SpaceAvailable: totalAvail,
		SpaceCapacity:  totalCap,
		Roots:          roots,
		PASVAddress:    s.bindIP,
	}
}

// getFileFromRoots finds a file across all roots, returns the full filesystem path.
func (s *Slave) getFileFromRoots(relPath string) (string, error) {
	for _, root := range s.rootsForVirtualPath(relPath) {
		fullPath := root.fullPath(relPath)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath, nil
		}
	}
	return "", fmt.Errorf("file not found: %s", relPath)
}

func (s *Slave) getFileFromRootsWithRoot(relPath string) (string, MountedRoot, error) {
	for _, root := range s.rootsForVirtualPath(relPath) {
		fullPath := root.fullPath(relPath)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath, root, nil
		}
	}
	return "", MountedRoot{}, fmt.Errorf("file not found: %s", relPath)
}

// getDirForUpload selects a root for a new upload (picks root with most free space).
func (s *Slave) getDirForUpload(relPath string) (string, error) {
	cleanRel := filepath.Clean(relPath)
	dirPart := filepath.Dir(cleanRel)
	roots := s.rootsForVirtualPath(relPath)
	var bestSeenAvail int64 = -1
	for _, root := range roots {
		avail, ok := s.rootHasUploadSpace(root)
		if avail > bestSeenAvail {
			bestSeenAvail = avail
		}
		if !ok {
			continue
		}
		existingDir := root.fullPath(dirPart)
		if info, err := os.Stat(existingDir); err == nil && info.IsDir() {
			if err := os.MkdirAll(existingDir, 0755); err != nil {
				return "", err
			}
			return root.fullPath(cleanRel), nil
		}
	}

	var bestRoot MountedRoot
	var bestAvail int64

	for _, root := range roots {
		avail, ok := s.rootHasUploadSpace(root)
		if avail > bestSeenAvail {
			bestSeenAvail = avail
		}
		if !ok {
			continue
		}
		if avail > bestAvail {
			bestAvail = avail
			bestRoot = root
		}
	}

	if bestRoot.Path == "" {
		if bestSeenAvail >= 0 && s.minUploadFreeBytes() > 0 {
			return "", s.lowUploadSpaceError(bestSeenAvail)
		}
		return "", fmt.Errorf("no root available")
	}

	fullDir := bestRoot.fullPath(dirPart)
	os.MkdirAll(fullDir, 0755)

	return bestRoot.fullPath(cleanRel), nil
}

func (s *Slave) minUploadFreeBytes() int64 {
	if s == nil || s.freeSpaceMB <= 0 {
		return 0
	}
	return int64(s.freeSpaceMB) * 1024 * 1024
}

func (s *Slave) rootHasUploadSpace(root MountedRoot) (int64, bool) {
	avail, _ := getDiskSpace(root.Path)
	minFree := s.minUploadFreeBytes()
	return avail, minFree <= 0 || avail >= minFree
}

func (s *Slave) lowUploadSpaceError(bestAvail int64) error {
	return fmt.Errorf("disk full: free space %.1f MB is below free_space_mb %d MB", float64(bestAvail)/(1024*1024), s.freeSpaceMB)
}

func (s *Slave) selectRootForRelocate(sourceRoot MountedRoot, toDir string) (MountedRoot, error) {
	destRoots := s.rootsForVirtualPath(toDir)
	if len(destRoots) == 0 {
		return MountedRoot{}, fmt.Errorf("no roots available")
	}
	var bestOther MountedRoot
	var bestOtherAvail int64 = -1
	for _, root := range destRoots {
		avail, _ := getDiskSpace(root.Path)
		if root.Path == sourceRoot.Path {
			continue
		}
		if avail > bestOtherAvail {
			bestOtherAvail = avail
			bestOther = root
		}
	}
	if bestOther.Path != "" {
		return bestOther, nil
	}
	for _, root := range destRoots {
		if root.Path == sourceRoot.Path {
			return root, nil
		}
	}
	return MountedRoot{}, fmt.Errorf("no alternate destination root available")
}

func copyPath(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyPath(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return os.Chtimes(dst, info.ModTime(), info.ModTime())
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

func (s *Slave) listenOnPortRange() (net.Listener, error) {
	if s.pasvPortMin > 0 && s.pasvPortMax >= s.pasvPortMin {
		span := s.pasvPortMax - s.pasvPortMin + 1
		start := int(atomic.AddUint32(&s.pasvNext, 1)-1) % span
		for i := 0; i < span; i++ {
			port := s.pasvPortMin + ((start + i) % span)
			bindAddr := net.JoinHostPort(s.localBindIP, strconv.Itoa(port))
			l, err := net.Listen("tcp", bindAddr)
			if err == nil {
				return l, nil
			}
		}
		return nil, fmt.Errorf("no available port in range %d-%d", s.pasvPortMin, s.pasvPortMax)
	}
	// Random port
	return net.Listen("tcp", net.JoinHostPort(s.localBindIP, "0"))
}

func (s *Slave) removeTransfer(idx int32) {
	if value, ok := s.transfers.LoadAndDelete(idx); ok {
		if t, ok := value.(*Transfer); ok && t != nil {
			s.unregisterUpload(t)
		}
	}
}

func (s *Slave) cleanEmptyParents(path string, root string) {
	dir := filepath.Dir(path)
	for dir != root && len(dir) > len(root) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			break
		}
		os.Remove(dir)
		dir = filepath.Dir(dir)
	}
}

func (s *Slave) hasActiveTransferUnder(relPath string) bool {
	relPath = filepath.ToSlash(filepath.Clean(strings.TrimSpace(relPath)))
	if relPath == "." {
		relPath = "/"
	}
	if !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}
	busy := false
	s.transfers.Range(func(_, value interface{}) bool {
		t, ok := value.(*Transfer)
		if !ok || t == nil {
			return true
		}
		transferPath := filepath.ToSlash(filepath.Clean(strings.TrimSpace(t.Path())))
		if transferPath == "." || transferPath == "" {
			return true
		}
		if !strings.HasPrefix(transferPath, "/") {
			transferPath = "/" + transferPath
		}
		if transferPath == relPath || strings.HasPrefix(transferPath, relPath+"/") || strings.HasPrefix(relPath, transferPath+"/") {
			busy = true
			return false
		}
		return true
	})
	return busy
}

func (s *Slave) shutdown() {
	log.Printf("[Slave] Shutting down")
	s.online.Store(false)
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *Slave) GetRoots() []string {
	return s.physicalRoots()
}

func (s *Slave) GetStream() *protocol.ObjectStream {
	return s.stream
}
