package master

import (
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"weaveftpd/internal/core"
	"weaveftpd/internal/metrics"
	"weaveftpd/internal/netutil"
	"weaveftpd/internal/plugin"
	"weaveftpd/internal/protocol"
)

// Bridge implements core.MasterBridge by wrapping a SlaveManager.
// It's the glue between the FTP command layer (core) and the slave management layer (master).
type Bridge struct {
	sm     *SlaveManager
	raceDB *RaceDB
	nukeDB *core.NukeHistoryDB

	cacheMu                sync.Mutex
	readFileCache          map[string]cachedReadFileResult
	liveTransferStatsCache []core.LiveTransferStat
	liveTransferStatsAt    time.Time
	liveTransferStatsMu    sync.Mutex
	listingDiagnosticAt    map[string]time.Time

	pendingUploads sync.Map          // clean virtual path -> pendingUpload, visible to FTP listings only
	uploadRecords  chan uploadRecord // async race-DB upload writes, off the 226 path
}

type pendingUpload struct {
	path      string
	slaveName string
	owner     string
	group     string
	started   time.Time
}

type uploadRecord struct {
	filePath string
	owner    string
	group    string
	size     int64
	duration int64
	checksum uint32
}

func configureBridgeDataSocket(conn net.Conn) {
	netutil.ConfigureDataSocket(conn, netutil.DefaultDataSocketBufferSize)
}

type cachedReadFileResult struct {
	content []byte
	errText string
	expires time.Time
}

var zipPayloadNameRE = regexp.MustCompile(`(?i)\.(zip|z\d\d)$`)

const (
	readFileCacheTTL          = 2 * time.Second
	liveTransferStatsCacheTTL = 1 * time.Second
	bridgeTransferBufferSize  = 4 * 1024 * 1024
	pendingUploadTTL          = 10 * time.Minute
)

var bridgeTransferBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, bridgeTransferBufferSize)
		return &buf
	},
}

func copyBridgeData(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := bridgeTransferBufferPool.Get().(*[]byte)
	defer bridgeTransferBufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

func isZipMainArchivePath(filePath string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(path.Base(filePath))), ".zip")
}

// NewBridge creates a new Bridge adapter.
func NewBridge(sm *SlaveManager) *Bridge {
	b := &Bridge{
		sm:            sm,
		readFileCache: make(map[string]cachedReadFileResult),
	}
	ndb, err := core.GetNukeHistoryDB(false)
	if err != nil {
		log.Printf("[Bridge] Nuke DB disabled: %v", err)
	} else {
		b.nukeDB = ndb
	}
	rdb, err := NewRaceDB("userdata/race.db")
	if err != nil {
		log.Printf("[Bridge] Race DB disabled: %v", err)
		return b
	}
	b.raceDB = rdb
	// Drain upload records to the race DB asynchronously so the per-file DB write
	// never sits on the upload-completion path before the 226.
	b.uploadRecords = make(chan uploadRecord, 8192)
	go b.uploadRecordWriter()
	if err := b.raceDB.Reconcile(sm.GetVFS()); err != nil {
		log.Printf("[Bridge] Race DB reconcile failed: %v", err)
	}
	if hydrated, err := b.raceDB.HydrateVFS(sm.GetVFS()); err != nil {
		log.Printf("[Bridge] Race DB VFS hydrate failed: %v", err)
	} else if hydrated > 0 {
		log.Printf("[Bridge] Hydrated %d persisted race file entries into VFS", hydrated)
	}
	return b
}

func (b *Bridge) StartRemergeJobs(slaveName string) (int, []string) {
	return b.sm.StartRemergeJobs(slaveName)
}

func (b *Bridge) StartRemergeJob(slaveName, jobName, overridePath string) (int, []string) {
	return b.sm.StartRemergeJob(slaveName, jobName, overridePath)
}

func (b *Bridge) StartRemergeAllJobs() (int, []string) {
	return b.sm.StartRemergeAllJobs()
}

func (b *Bridge) StartRemergeAllJob(jobName, overridePath string) (int, []string) {
	return b.sm.StartRemergeAllJob(jobName, overridePath)
}

func (b *Bridge) StopRemerge(slaveName string) error {
	return b.sm.StopRemerge(slaveName)
}

func (b *Bridge) StopRemergeAll() (int, []string) {
	return b.sm.StopRemergeAll()
}

func (b *Bridge) GetLiveTransferStats() []core.LiveTransferStat {
	return b.getLiveTransferStats(true)
}

func (b *Bridge) GetLiveTransferStatsFresh() []core.LiveTransferStat {
	return b.getLiveTransferStats(false)
}

func (b *Bridge) getLiveTransferStats(useCache bool) []core.LiveTransferStat {
	if b == nil || b.sm == nil {
		return nil
	}
	if useCache {
		if cached, ok := b.cachedLiveTransferStats(liveTransferStatsCacheTTL); ok {
			return cached
		}
		// Return the last snapshot even on expiry or first use. Only one
		// refresh runs, and listings never wait for its mutex or slave replies.
		cached, _ := b.cachedLiveTransferStats(0)
		if b.liveTransferStatsMu.TryLock() {
			go func() {
				defer b.liveTransferStatsMu.Unlock()
				if _, ok := b.cachedLiveTransferStats(liveTransferStatsCacheTTL); !ok {
					b.refreshLiveTransferStats()
				}
			}()
		}
		return cached
	}
	b.liveTransferStatsMu.Lock()
	defer b.liveTransferStatsMu.Unlock()
	return b.refreshLiveTransferStats()
}

// Caller holds liveTransferStatsMu. Explicit fresh callers (upload completion)
// can still wait; listing callers run this in the background.
func (b *Bridge) refreshLiveTransferStats() []core.LiveTransferStat {
	started := time.Now()
	defer func() { b.logListingDelay("slave-statistics", "", time.Since(started), nil) }()
	slaves := b.sm.GetAllSlaves()
	previous, _ := b.cachedLiveTransferStats(0)
	type result struct {
		stats []core.LiveTransferStat
	}
	results := make(chan result, len(slaves))
	var wg sync.WaitGroup
	for _, slave := range slaves {
		if slave == nil || !slave.IsOnline() {
			continue
		}
		wg.Add(1)
		go func(slave *RemoteSlave) {
			defer wg.Done()
			started := time.Now()
			failed := func(err error) {
				b.logListingDelay("slave-statistics:"+slave.Name(), "", time.Since(started), err)
				// A failed refresh is not evidence that active uploads ended.
				var retained []core.LiveTransferStat
				for _, stat := range previous {
					if stat.SlaveName == slave.Name() {
						retained = append(retained, stat)
					}
				}
				results <- result{stats: retained}
			}
			idx, err := IssueTransferStats(slave)
			if err != nil {
				failed(err)
				return
			}
			resp, err := slave.FetchResponse(idx, 5*time.Second)
			if err != nil {
				failed(err)
				return
			}
			statsResp, ok := resp.(*protocol.AsyncResponseTransferStats)
			if !ok {
				failed(fmt.Errorf("unexpected transfer statistics response %T", resp))
				return
			}
			out := make([]core.LiveTransferStat, 0, len(statsResp.Stats))
			for _, stat := range statsResp.Stats {
				direction := ""
				switch stat.Direction {
				case 'R':
					direction = "upload"
				case 'S':
					direction = "download"
				}
				if direction == "" {
					continue
				}
				var startedAt time.Time
				if stat.StartedUnixMs > 0 {
					startedAt = time.UnixMilli(stat.StartedUnixMs)
				}
				out = append(out, core.LiveTransferStat{
					SlaveName:     slave.Name(),
					TransferIndex: stat.TransferIndex,
					Direction:     direction,
					Path:          stat.Path,
					StartedAt:     startedAt,
					Transferred:   stat.Transferred,
					SpeedBytes:    float64(stat.SpeedBytes),
				})
			}
			if len(out) > 0 {
				results <- result{stats: out}
			}
		}(slave)
	}
	wg.Wait()
	close(results)

	var out []core.LiveTransferStat
	for res := range results {
		out = append(out, res.stats...)
	}
	b.cacheMu.Lock()
	b.liveTransferStatsCache = append([]core.LiveTransferStat(nil), out...)
	b.liveTransferStatsAt = time.Now()
	b.cacheMu.Unlock()
	return out
}

func (b *Bridge) cachedLiveTransferStats(maxAge time.Duration) ([]core.LiveTransferStat, bool) {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	if b.liveTransferStatsAt.IsZero() {
		return nil, false
	}
	if maxAge > 0 && time.Since(b.liveTransferStatsAt) >= maxAge {
		return nil, false
	}
	return append([]core.LiveTransferStat(nil), b.liveTransferStatsCache...), true
}

func (b *Bridge) GetAggregateDiskUsage() (freeBytes int64, totalBytes int64, ok bool) {
	if b == nil || b.sm == nil {
		return 0, 0, false
	}
	for _, slave := range b.sm.GetAllSlaves() {
		if slave == nil || !slave.IsOnline() {
			continue
		}
		if b.sm.IsSlaveReadOnly(slave.Name()) {
			continue
		}
		status := slave.GetDiskStatus()
		if status.SpaceCapacity <= 0 {
			continue
		}
		freeBytes += status.SpaceAvailable
		totalBytes += status.SpaceCapacity
		ok = true
	}
	return freeBytes, totalBytes, ok
}

func (b *Bridge) AbortTransfer(slaveName string, transferIndex int32, reason string) bool {
	if b == nil || b.sm == nil || transferIndex == 0 {
		return false
	}
	slave := b.sm.GetSlave(strings.TrimSpace(slaveName))
	if slave == nil || !slave.IsOnline() {
		return false
	}
	if strings.TrimSpace(reason) == "" {
		reason = "aborted by slowkick"
	}
	IssueAbort(slave, transferIndex, reason)
	return true
}

func (b *Bridge) ListSlaveAuthDenyEntries() []string {
	if b == nil || b.sm == nil {
		return nil
	}
	return b.sm.ListAuthDenyEntries()
}

func (b *Bridge) AddSlaveAuthDenyEntry(entry string) (string, error) {
	if b == nil || b.sm == nil {
		return "", fmt.Errorf("master not initialized")
	}
	return b.sm.AddAuthDenyEntry(entry)
}

func (b *Bridge) RemoveSlaveAuthDenyEntry(entry string) (bool, error) {
	if b == nil || b.sm == nil {
		return false, fmt.Errorf("master not initialized")
	}
	return b.sm.RemoveAuthDenyEntry(entry)
}

func (b *Bridge) ClearSlaveAuthTempBan(entry string) (bool, error) {
	if b == nil || b.sm == nil {
		return false, fmt.Errorf("master not initialized")
	}
	return b.sm.ClearAuthTempBan(entry)
}

func (b *Bridge) ListSlaveAuthTempBans() []core.SlaveAuthBanInfo {
	if b == nil || b.sm == nil {
		return nil
	}
	snaps := b.sm.ListAuthTempBans()
	out := make([]core.SlaveAuthBanInfo, 0, len(snaps))
	for _, snap := range snaps {
		out = append(out, core.SlaveAuthBanInfo{
			IP:          snap.IP,
			Strikes:     snap.Strikes,
			BannedUntil: snap.BannedUntil,
		})
	}
	return out
}

func (b *Bridge) AddSlaveMask(name, mask string) error {
	if b == nil || b.sm == nil {
		return fmt.Errorf("master not initialized")
	}
	return b.sm.AddSlaveMask(name, mask)
}

func (b *Bridge) RemoveSlaveMask(name, mask string) (bool, error) {
	if b == nil || b.sm == nil {
		return false, fmt.Errorf("master not initialized")
	}
	return b.sm.RemoveSlaveMask(name, mask)
}

func (b *Bridge) ListSlaveMasks(name string) []string {
	if b == nil || b.sm == nil {
		return nil
	}
	return b.sm.ListSlaveMasks(name)
}

func (b *Bridge) ListAllSlaveMasks() map[string][]string {
	if b == nil || b.sm == nil {
		return nil
	}
	return b.sm.ListAllSlaveMasks()
}

func (b *Bridge) RunOnSlaveCommand(dirPath, command string, args []string, env map[string]string, timeoutSeconds int, preferredSlave string) (string, error) {
	slave := b.resolveSlaveForDir(dirPath, preferredSlave)
	if slave == nil {
		return "", fmt.Errorf("no available slave found for %s", dirPath)
	}
	index, err := IssueRunCommand(slave, command, args, env, timeoutSeconds, dirPath)
	if err != nil {
		return "", err
	}
	resp, err := slave.FetchResponse(index, time.Duration(timeoutSeconds+5)*time.Second)
	if err != nil {
		return "", err
	}
	if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
		return "", fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
	}
	if result, ok := resp.(*protocol.AsyncResponseCommandResult); ok {
		return result.Output, nil
	}
	return "", fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
}

func (b *Bridge) resolveSlaveForDir(dirPath, preferredSlave string) *RemoteSlave {
	if strings.TrimSpace(preferredSlave) != "" {
		slave := b.sm.GetSlave(preferredSlave)
		if slave != nil && slave.IsOnline() {
			return slave
		}
	}

	entries := b.ListDir(dirPath)
	for _, entry := range entries {
		if strings.TrimSpace(entry.Slave) == "" {
			continue
		}
		if slave := b.sm.GetSlave(entry.Slave); slave != nil && slave.IsOnline() {
			return slave
		}
	}

	for _, slaveName := range b.sm.GetVFS().GetSlavesForPath(dirPath) {
		if slave := b.sm.GetSlave(slaveName); slave != nil && slave.IsOnline() {
			return slave
		}
	}
	return nil
}

// Ensure Bridge implements MasterBridge at compile time.
var _ core.MasterBridge = (*Bridge)(nil)
var _ plugin.MasterBridge = (*Bridge)(nil)

// ListDir returns directory entries from the master's VFS.
func (b *Bridge) ListDir(dirPath string) []core.MasterFileEntry {
	started := time.Now()
	defer func() { b.logListingDelay("list-directory", dirPath, time.Since(started), nil) }()
	vfsFiles := b.sm.GetVFS().ListDirectory(dirPath)
	if b.repairZeroSizeListEntries(dirPath, vfsFiles) {
		vfsFiles = b.sm.GetVFS().ListDirectory(dirPath)
	}
	entries := make([]core.MasterFileEntry, 0, len(vfsFiles)+3)
	seen := make(map[string]struct{}, len(vfsFiles))
	for _, f := range vfsFiles {
		if f == nil {
			continue
		}
		entries = append(entries, masterEntryFromVFSFile(f))
		seen[strings.ToLower(strings.TrimSpace(path.Base(f.Path)))] = struct{}{}
	}
	for _, entry := range b.pendingUploadEntriesForDir(dirPath) {
		if _, ok := seen[strings.ToLower(strings.TrimSpace(entry.Name))]; ok {
			b.clearPendingUpload(path.Join(dirPath, entry.Name))
			continue
		}
		entries = append(entries, entry)
	}
	entries = append(entries, b.virtualNukeEntries(dirPath)...)
	sort.SliceStable(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries
}

func (b *Bridge) notePendingUpload(filePath, slaveName, owner, group string, position int64) {
	if b == nil || position > 0 || !isPendingUploadListVisible(filePath) {
		return
	}
	cleanPath := cleanBridgePath(filePath)
	b.pendingUploads.Store(cleanPath, pendingUpload{
		path:      cleanPath,
		slaveName: strings.TrimSpace(slaveName),
		owner:     strings.TrimSpace(owner),
		group:     strings.TrimSpace(group),
		started:   time.Now(),
	})
}

func (b *Bridge) clearPendingUpload(filePath string) {
	if b == nil {
		return
	}
	b.pendingUploads.Delete(cleanBridgePath(filePath))
}

func (b *Bridge) pendingUploadForPath(filePath string) (pendingUpload, bool) {
	if b == nil {
		return pendingUpload{}, false
	}
	cleanPath := cleanBridgePath(filePath)
	val, ok := b.pendingUploads.Load(cleanPath)
	if !ok {
		return pendingUpload{}, false
	}
	pu, ok := val.(pendingUpload)
	if !ok || time.Since(pu.started) > pendingUploadTTL {
		b.pendingUploads.Delete(cleanPath)
		return pendingUpload{}, false
	}
	return pu, true
}

func (b *Bridge) pendingUploadEntriesForDir(dirPath string) []core.MasterFileEntry {
	if b == nil {
		return nil
	}
	cleanDir := cleanBridgePath(dirPath)
	now := time.Now()
	out := make([]core.MasterFileEntry, 0, 1)
	b.pendingUploads.Range(func(key, value interface{}) bool {
		pu, ok := value.(pendingUpload)
		if !ok || now.Sub(pu.started) > pendingUploadTTL {
			b.pendingUploads.Delete(key)
			return true
		}
		if cleanBridgePath(path.Dir(pu.path)) != cleanDir {
			return true
		}
		out = append(out, pendingUploadEntry(pu))
		return true
	})
	return out
}

func pendingUploadEntry(pu pendingUpload) core.MasterFileEntry {
	owner := pu.owner
	if owner == "" {
		owner = "WeaveFTPd"
	}
	group := pu.group
	if group == "" {
		group = "WeaveFTPd"
	}
	modTime := pu.started.Unix()
	if modTime <= 0 {
		modTime = time.Now().Unix()
	}
	return core.MasterFileEntry{
		Name:    path.Base(pu.path),
		Size:    1,
		ModTime: modTime,
		Owner:   owner,
		Group:   group,
		Slave:   pu.slaveName,
	}
}

func isPendingUploadListVisible(filePath string) bool {
	name := strings.ToLower(strings.TrimSpace(path.Base(filePath)))
	return strings.HasSuffix(name, ".sfv")
}

func cleanBridgePath(filePath string) string {
	cleanPath := cleanBridgeVFSPath(strings.TrimSpace(filePath))
	if cleanPath == "." || cleanPath == "" {
		return "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	return path.Clean(cleanPath)
}

func (b *Bridge) selectSlaveForDownloadIncludingPending(filePath string) *RemoteSlave {
	if b == nil || b.sm == nil {
		return nil
	}
	if slave := b.sm.SelectSlaveForDownload(filePath); slave != nil {
		return slave
	}
	pu, ok := b.pendingUploadForPath(filePath)
	if !ok || strings.TrimSpace(pu.slaveName) == "" {
		return nil
	}
	slave := b.sm.GetSlave(pu.slaveName)
	if slave == nil || !slave.IsOnline() {
		return nil
	}
	return slave
}

// zeroSizeRepairCache throttles only the per-directory DB query below (not the
// repair itself): dirPath -> cached verified-present records + fetch time.
var zeroSizeRepairCache sync.Map

const zeroSizeRepairTTL = 1 * time.Second

type zeroSizeRepairState struct {
	at      time.Time
	records map[string]ReleaseFileRecord
}

func (b *Bridge) repairZeroSizeListEntries(dirPath string, files []*VFSFile) bool {
	if b == nil || b.raceDB == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return false
	}

	// Trigger on any suspect entry. A completed file can be left with a non-zero
	// partial VFS size, so delaying non-zero repair exposes that short size to
	// racing clients. The per-directory DB result cache below bounds the lookup.
	needsRepair := false
	for _, f := range files {
		if f == nil || f.IsDir || f.IsSymlink {
			continue
		}
		if f.Size <= 0 || (f.Checksum == 0 && f.XferTime == 0) {
			needsRepair = true
			break
		}
	}
	if !needsRepair {
		return false
	}

	// Pull verified-present sizes from the race DB so a completed file that
	// momentarily reads size 0 in the VFS is never served to a racing client as
	// 0 bytes -- cbftp will not queue a 0-byte file, so a 0-byte .sfv is silently
	// dropped from the race. The DB query is throttled per directory by a short
	// TTL, but the repair still runs from the (cached or fresh) records, so a
	// just-completed file is restored on the very next listing instead of being
	// withheld for seconds by a query debounce. Verified sizes are final, so the
	// cached records are safe to reuse within the TTL.
	now := time.Now()
	var records map[string]ReleaseFileRecord
	if cached, ok := zeroSizeRepairCache.Load(dirPath); ok {
		if st, ok := cached.(zeroSizeRepairState); ok && now.Sub(st.at) < zeroSizeRepairTTL {
			records = st.records
		}
	}
	if records == nil {
		started := time.Now()
		fresh, err := b.raceDB.VerifiedPresentFiles(dirPath)
		b.logListingDelay("race-db-repair", dirPath, time.Since(started), err)
		if err != nil {
			return false
		}
		records = fresh
		zeroSizeRepairCache.Store(dirPath, zeroSizeRepairState{at: now, records: fresh})
	}
	if len(records) == 0 {
		return false
	}

	repaired := false
	repairedCount := 0
	for _, f := range files {
		if f == nil || f.IsDir || f.IsSymlink {
			continue
		}
		rec := records[raceDBFileKey(path.Base(f.Path))]
		// Repair when the authoritative verified size is larger than what the VFS
		// shows -- covers both a 0-byte entry and a stuck short partial (e.g. 444k).
		if rec.SizeBytes <= 0 || rec.SizeBytes <= f.Size {
			continue
		}
		if b.sm.GetVFS().HydrateRaceFile(f.Path, rec.Owner, rec.Group, rec.SizeBytes, rec.DurationMs, rec.Checksum) {
			repaired = true
			repairedCount++
			b.invalidateReadFileCache(f.Path)
		}
	}
	if repairedCount > 0 {
		// A file was on disk but read as size 0 in the VFS and we had to fix it
		// from the DB: exactly the state that makes racing clients skip+retry.
		metrics.ZeroSizeRepairs.Add(int64(repairedCount))
	}
	return repaired
}

// Rate-limit diagnostics by phase so a busy release cannot flood the log.
func (b *Bridge) logListingDelay(phase, dirPath string, elapsed time.Duration, err error) {
	if err == nil && elapsed < 250*time.Millisecond {
		return
	}
	now := time.Now()
	b.cacheMu.Lock()
	if now.Sub(b.listingDiagnosticAt[phase]) < 30*time.Second {
		b.cacheMu.Unlock()
		return
	}
	if b.listingDiagnosticAt == nil {
		b.listingDiagnosticAt = make(map[string]time.Time)
	}
	b.listingDiagnosticAt[phase] = now
	b.cacheMu.Unlock()
	log.Printf("[Bridge] listing diagnostic phase=%s path=%q elapsed=%s error=%v", phase, dirPath, elapsed, err)
}

func masterEntryFromVFSFile(f *VFSFile) core.MasterFileEntry {
	if f == nil {
		return core.MasterFileEntry{}
	}
	return core.MasterFileEntry{
		Name:       path.Base(f.Path),
		Size:       f.Size,
		IsDir:      f.IsDir,
		IsSymlink:  f.IsSymlink,
		LinkTarget: f.LinkTarget,
		Mode:       f.Mode,
		ModTime:    f.LastModified,
		Owner:      f.Owner,
		Group:      f.Group,
		Slave:      f.SlaveName,
		XferTime:   f.XferTime,
	}
}

func (b *Bridge) virtualNukeEntries(dirPath string) []core.MasterFileEntry {
	if b == nil || b.nukeDB == nil {
		return nil
	}
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	if !strings.HasPrefix(strings.ToUpper(path.Base(cleanDirPath)), "[NUKED]-") {
		return nil
	}
	entry, err := b.nukeDB.FindActiveByPath(cleanDirPath)
	if err != nil || entry == nil {
		return nil
	}
	return nukeVirtualEntriesFromHistory(entry)
}

func nukeVirtualEntriesFromHistory(entry *core.NukeHistoryEntry) []core.MasterFileEntry {
	if entry == nil {
		return nil
	}
	now := entry.NukedAt
	if now <= 0 {
		now = time.Now().Unix()
	}
	owner := strings.TrimSpace(entry.NukedBy)
	if owner == "" {
		owner = "weaveftpd"
	}
	group := "NUKED"
	multiplier := entry.Multiplier
	if multiplier <= 0 {
		multiplier = 1
	}
	out := make([]core.MasterFileEntry, 0, 3)
	if name := nukeVirtualEntryName("!NUKE", fmt.Sprintf("x%d", multiplier), entry.Reason); name != "" {
		out = append(out, core.MasterFileEntry{
			Name:    name,
			IsDir:   true,
			ModTime: now,
			Owner:   owner,
			Group:   group,
		})
	}
	if nukees := strings.TrimSpace(entry.Nukees); nukees != "" {
		if name := nukeVirtualEntryName("!NUKEES", nukees); name != "" {
			out = append(out, core.MasterFileEntry{
				Name:    name,
				IsDir:   true,
				ModTime: now,
				Owner:   owner,
				Group:   group,
			})
		}
	}
	if name := nukeVirtualEntryName("!NUKER", owner); name != "" {
		out = append(out, core.MasterFileEntry{
			Name:    name,
			IsDir:   true,
			ModTime: now,
			Owner:   owner,
			Group:   group,
		})
	}
	return out
}

func nukeVirtualEntryName(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "\x00", "", "\r", " ", "\n", " ")
	for _, part := range parts {
		part = strings.TrimSpace(replacer.Replace(part))
		part = strings.Join(strings.Fields(part), " ")
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	name := strings.Join(cleaned, " - ")
	if len(name) > 200 {
		name = strings.TrimSpace(name[:200])
	}
	return name
}

func (b *Bridge) PluginListDir(dirPath string) []plugin.FileEntry {
	coreEntries := b.ListDir(dirPath)
	entries := make([]plugin.FileEntry, 0, len(coreEntries))
	for _, e := range coreEntries {
		entries = append(entries, plugin.FileEntry{
			Name:       e.Name,
			Size:       e.Size,
			IsDir:      e.IsDir,
			IsSymlink:  e.IsSymlink,
			LinkTarget: e.LinkTarget,
			Mode:       e.Mode,
			ModTime:    e.ModTime,
			Owner:      e.Owner,
			Group:      e.Group,
			Slave:      e.Slave,
		})
	}
	return entries
}

// FindChildFoldMatch exposes the VFS case-insensitive child lookup to plugins
// (releaseguard) so the per-MKD dupe/case/nuked check avoids building a full
// directory listing. Accessed via optional interface, so it adds nothing to the
// plugin MasterBridge interface.
func (b *Bridge) FindChildFoldMatch(parentPath string, candidates []string) (string, int, bool) {
	if b == nil || b.sm == nil {
		return "", 0, false
	}
	return b.sm.GetVFS().FindChildFoldMatch(parentPath, candidates)
}

// UploadFile routes an upload from the FTP client to a slave.
//
// Flow ( STOR):
//  1. Select best slave
//  2. Tell slave to LISTEN (open passive data port)
//  3. Connect from master to slave's data port
//  4. Tell slave to RECEIVE the file
//  5. Bridge data: read from clientData, write to slave connection
//
// In  the FTP client connects directly to the slave's PASV port.
// Here we bridge through the master since the client already connected to us.
// A PRET-based optimization (redirect client to slave) can be added later.
func (b *Bridge) UploadFile(filePath string, clientData net.Conn, owner, group string, position int64, transferType byte) (int64, uint32, int64, error) {
	var slave *RemoteSlave
	if position > 0 {
		slave = b.sm.SelectSlaveForDownload(filePath)
		if slave == nil {
			return 0, 0, 0, fmt.Errorf("resume target not found: %s", filePath)
		}
	} else {
		slave = b.sm.SelectSlaveForUpload(filePath)
	}
	if slave == nil {
		return 0, 0, 0, fmt.Errorf("no available slave")
	}

	slave.IncActiveTransfers()
	defer slave.DecActiveTransfers()

	// Tell slave to listen
	listenIdx, err := IssueListen(slave, false, false)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("issue listen to %s: %w", slave.Name(), err)
	}

	resp, err := slave.FetchResponse(listenIdx, 60*time.Second)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("slave %s listen failed: %w", slave.Name(), err)
	}

	transferResp, ok := resp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return 0, 0, 0, fmt.Errorf("unexpected response from slave")
	}

	slaveAddr := net.JoinHostPort(slave.GetPASVIP(), strconv.Itoa(transferResp.Info.Port))
	log.Printf("[Bridge] Connecting to slave %s at %s for upload of %s", slave.Name(), slaveAddr, filePath)

	// Connect to slave's data port
	slaveConn, err := net.DialTimeout("tcp", slaveAddr, 10*time.Second)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("connect to slave data port: %w", err)
	}
	configureBridgeDataSocket(slaveConn)

	// Tell slave to receive the file
	recvIdx, err := IssueReceive(slave, filePath, transferType, position, "master",
		transferResp.Info.TransferIndex)
	if err != nil {
		slaveConn.Close()
		return 0, 0, 0, fmt.Errorf("issue receive: %w", err)
	}

	// Wait for receive acknowledgement
	_, err = slave.FetchResponse(recvIdx, 60*time.Second)
	if err != nil {
		slaveConn.Close()
		return 0, 0, 0, fmt.Errorf("receive ack: %w", err)
	}
	b.notePendingUpload(filePath, slave.Name(), owner, group, position)
	defer b.clearPendingUpload(filePath)

	// Bridge: client -> slave. The slave calculates and returns the authoritative CRC.
	bridgeStart := time.Now()
	written, err := copyBridgeData(slaveConn, clientData)
	xferTime := time.Since(bridgeStart).Milliseconds()
	var checksum uint32
	slaveConn.Close()

	status, statusErr := slave.WaitTransferStatus(transferResp.Info.TransferIndex, 2*time.Hour)
	if err != nil {
		if statusErr == nil && status.Error != "" {
			b.reconcileFailedUploadState(filePath, slave)
			return status.Transferred, status.Checksum, status.Elapsed, fmt.Errorf("%s", status.Error)
		}
		if statusErr != nil {
			b.reconcileFailedUploadState(filePath, slave)
		}
		log.Printf("[Bridge] Upload bridge error: %v (wrote %d bytes)", err, written)
		return written, checksum, 0, fmt.Errorf("upload bridge: %w", err)
	}
	if statusErr != nil {
		b.reconcileFailedUploadState(filePath, slave)
		return written, checksum, 0, statusErr
	}
	if status.Error != "" {
		b.reconcileFailedUploadState(filePath, slave)
		return status.Transferred, status.Checksum, status.Elapsed, fmt.Errorf("%s", status.Error)
	}

	finalSize := finalUploadFileSize(status, position)
	xferTime = status.Elapsed
	checksum = status.Checksum
	if position > 0 {
		finalChecksum, err := b.ChecksumFile(filePath)
		if err != nil {
			return written, checksum, xferTime, fmt.Errorf("resume checksum: %w", err)
		}
		checksum = finalChecksum
	}

	log.Printf("[Bridge] Uploaded %s to slave %s (%d bytes, %dms, CRC=%08X, offset=%d)", filePath, slave.Name(), finalSize, xferTime, checksum, position)

	// Add file to VFS with transfer timing and checksum
	b.sm.GetVFS().AddFile(filePath, VFSFile{
		Path:         filePath,
		Size:         finalSize,
		IsDir:        false,
		LastModified: time.Now().Unix(),
		SlaveName:    slave.Name(),
		Owner:        owner,
		Group:        group,
		XferTime:     xferTime,
		Checksum:     checksum,
		Seen:         true,
	})
	b.recordUploadMetadata(filePath, owner, group, finalSize, xferTime, checksum)
	b.sm.SyncStatusMarkersForPath(filePath, false)

	return finalSize, checksum, xferTime, nil
}

func finalUploadFileSize(status protocol.TransferStatus, position int64) int64 {
	if status.FileSize > 0 {
		return status.FileSize
	}
	if position > 0 {
		return status.Transferred + position
	}
	return status.Transferred
}

func (b *Bridge) repairDownloadedFileSize(filePath string, sizeBytes int64) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil || sizeBytes <= 0 {
		return
	}
	if !b.sm.GetVFS().UpdateFileTransferSize(filePath, sizeBytes) {
		return
	}
	b.invalidateReadFileCache(filePath)
	b.sm.InvalidateReleaseStateForPath(filePath, false)
	b.sm.SyncStatusMarkersForPath(filePath, false)
}

func (b *Bridge) recordUploadMetadata(filePath, owner, group string, size int64, durationMs int64, checksum uint32) {
	if b == nil || b.raceDB == nil || size <= 0 || durationMs <= 0 {
		return
	}
	rec := uploadRecord{filePath: filePath, owner: owner, group: group, size: size, duration: durationMs, checksum: checksum}
	if b.uploadRecords != nil {
		select {
		case b.uploadRecords <- rec:
			return
		default:
			// Queue full; fall through to a synchronous write rather than drop
			// race data. This only happens under extreme backlog.
		}
	}
	b.writeUploadRecord(rec)
}

// uploadRecordWriter drains queued upload records to the race DB on a single
// background goroutine, keeping the DB write off the upload-completion path.
func (b *Bridge) uploadRecordWriter() {
	for rec := range b.uploadRecords {
		b.writeUploadRecord(rec)
	}
}

func (b *Bridge) writeUploadRecord(rec uploadRecord) {
	if b == nil || b.raceDB == nil {
		return
	}
	cleanPath := cleanBridgeVFSPath(rec.filePath)
	if err := b.raceDB.RecordUpload(cleanPath, rec.owner, rec.group, rec.size, rec.duration, rec.checksum); err != nil {
		log.Printf("[Bridge] Race DB record upload failed for %s: %v", rec.filePath, err)
		return
	}
	zeroSizeRepairCache.Delete(path.Dir(cleanPath))
}

// DownloadFile routes a download from a slave to the FTP client.
//
// Flow ( RETR):
//  1. Find which slave has the file
//  2. Tell slave to LISTEN
//  3. Connect from master to slave's data port
//  4. Tell slave to SEND the file
//  5. Bridge data: read from slave, write to clientData
func (b *Bridge) DownloadFile(filePath string, clientData net.Conn, username, primaryGroup string, position int64, transferType byte) (uint32, error) {
	slave := b.selectSlaveForDownloadIncludingPending(filePath)
	if slave == nil {
		return 0, fmt.Errorf("file not found on any available slave: %s", filePath)
	}

	slave.IncActiveTransfers()
	defer slave.DecActiveTransfers()

	// Tell slave to listen
	listenIdx, err := IssueListen(slave, false, false)
	if err != nil {
		return 0, fmt.Errorf("issue listen to %s: %w", slave.Name(), err)
	}

	resp, err := slave.FetchResponse(listenIdx, 60*time.Second)
	if err != nil {
		return 0, fmt.Errorf("slave %s listen failed: %w", slave.Name(), err)
	}

	transferResp, ok := resp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return 0, fmt.Errorf("unexpected response from slave")
	}

	slaveAddr := net.JoinHostPort(slave.GetPASVIP(), strconv.Itoa(transferResp.Info.Port))
	log.Printf("[Bridge] Connecting to slave %s at %s for download of %s", slave.Name(), slaveAddr, filePath)

	slaveConn, err := net.DialTimeout("tcp", slaveAddr, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("connect to slave data port: %w", err)
	}
	configureBridgeDataSocket(slaveConn)

	// Tell slave to send the file
	sendIdx, err := IssueSend(slave, filePath, transferType, position, "master",
		transferResp.Info.TransferIndex)
	if err != nil {
		slaveConn.Close()
		return 0, fmt.Errorf("issue send: %w", err)
	}

	_, err = slave.FetchResponse(sendIdx, 60*time.Second)
	if err != nil {
		slaveConn.Close()
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, fmt.Errorf("send ack: %w", err)
	}

	// Bridge: slave -> client
	written, err := copyBridgeData(clientData, slaveConn)
	slaveConn.Close()
	status, statusErr := slave.WaitTransferStatus(transferResp.Info.TransferIndex, 2*time.Hour)

	if err != nil {
		log.Printf("[Bridge] Download bridge error: %v (wrote %d bytes)", err, written)
		return 0, fmt.Errorf("download bridge: %w", err)
	}
	if statusErr != nil {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, statusErr
	}
	if status.Error != "" {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, fmt.Errorf("%s", status.Error)
	}

	log.Printf("[Bridge] Downloaded %s from slave %s (%d bytes, offset=%d)", filePath, slave.Name(), written, position)
	if position > 0 {
		return 0, nil
	}
	b.repairDownloadedFileSize(filePath, status.Transferred)
	return status.Checksum, nil
}

// DeleteFile deletes from all slaves and VFS.
func (b *Bridge) DeleteFile(filePath string) error {
	b.clearPendingUpload(filePath)
	vfsFile := b.sm.GetVFS().GetFile(filePath)
	err := b.sm.DeleteFile(filePath)
	if err != nil {
		return err
	}
	b.cleanupZipDizAfterDelete(filePath)
	if b.raceDB != nil {
		isDir := vfsFile != nil && vfsFile.IsDir
		if derr := b.raceDB.DeletePath(cleanBridgeVFSPath(filePath), isDir); derr != nil {
			log.Printf("[Bridge] Race DB delete sync failed for %s: %v", filePath, derr)
		}
	}
	b.invalidateReadFileCache(filePath)
	b.sm.InvalidateReleaseStateForPath(filePath, vfsFile != nil && vfsFile.IsDir)
	b.sm.SyncStatusMarkersForPath(filePath, vfsFile != nil && vfsFile.IsDir)
	return nil
}

func (b *Bridge) cleanupZipDizAfterDelete(filePath string) {
	if b == nil || b.sm == nil {
		return
	}
	if !isZipMainArchivePath(filePath) {
		return
	}
	dirPath := path.Dir(cleanBridgeVFSPath(filePath))
	entries := b.ListDir(dirPath)
	for _, entry := range entries {
		if entry.IsDir || entry.IsSymlink {
			continue
		}
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(entry.Name)), ".zip") {
			return
		}
	}
	dizPath := path.Join(dirPath, "file_id.diz")
	if b.sm.GetVFS().FileExists(dizPath) {
		if err := b.sm.DeleteFile(dizPath); err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
			log.Printf("[Bridge] zip diz cleanup failed for %s: %v", dirPath, err)
		}
	}
}

// RenameFile renames on the owning slave and VFS.
func (b *Bridge) RenameFile(from, toDir, toName string) error {
	vfsFile := b.sm.GetVFS().GetFile(from)
	toPath := path.Join(toDir, toName)
	if err := b.sm.RenameFile(from, toDir, toName); err != nil {
		return err
	}
	if isZipMainArchivePath(from) && !isZipMainArchivePath(toPath) {
		b.cleanupZipDizAfterDelete(from)
	}
	if b.raceDB != nil {
		isDir := vfsFile != nil && vfsFile.IsDir
		if err := b.raceDB.RenamePath(cleanBridgeVFSPath(from), cleanBridgeVFSPath(toPath), isDir); err != nil {
			log.Printf("[Bridge] Race DB rename sync failed from %s to %s: %v", from, toPath, err)
		}
	}
	b.sm.RenameReleaseState(from, toPath, vfsFile != nil && vfsFile.IsDir)
	b.sm.SyncStatusMarkersForPath(from, vfsFile != nil && vfsFile.IsDir)
	b.sm.SyncStatusMarkersForPath(toPath, vfsFile != nil && vfsFile.IsDir)
	return nil
}

// VFSMoveOnly updates the master's metadata after an external tool has already
// moved a path and verified the bytes. It intentionally does not touch disk.
func (b *Bridge) VFSMoveOnly(from, to, slaveName string) error {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return fmt.Errorf("master bridge unavailable")
	}
	from = cleanBridgeVFSPath(from)
	to = cleanBridgeVFSPath(to)
	if from == "/" || to == "/" {
		return fmt.Errorf("refusing to move VFS root")
	}
	if strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" || from == to {
		return fmt.Errorf("invalid VFS move %q -> %q", from, to)
	}
	vfs := b.sm.GetVFS()
	file := vfs.GetFile(from)
	if file == nil {
		return fmt.Errorf("source path not found in VFS: %s", from)
	}
	if existing := vfs.GetFile(to); existing != nil {
		return fmt.Errorf("destination already exists in VFS: %s", to)
	}
	slaveName = strings.TrimSpace(slaveName)
	parentSlave := file.SlaveName
	if slaveName != "" {
		if slave := b.sm.GetSlave(slaveName); slave == nil {
			return fmt.Errorf("unknown slave %q", slaveName)
		}
		parentSlave = slaveName
	}
	b.ensureVFSParents(to, parentSlave)
	if slaveName != "" {
		vfs.RelocateFile(from, to, slaveName)
	} else {
		vfs.RenameFile(from, to)
	}
	if b.raceDB != nil {
		if err := b.raceDB.RenamePath(cleanBridgeVFSPath(from), cleanBridgeVFSPath(to), file.IsDir); err != nil {
			log.Printf("[Bridge] Race DB VFS-only rename sync failed %s -> %s: %v", from, to, err)
		}
	}
	b.invalidateReadFileCache(from)
	b.invalidateReadFileCache(to)
	b.sm.RenameReleaseState(from, to, file.IsDir)
	b.sm.SyncStatusMarkersForPath(from, file.IsDir)
	b.sm.SyncStatusMarkersForPath(to, file.IsDir)
	return nil
}

// VFSDeleteOnly removes a path from master metadata after an external tool has
// already deleted it from storage. It intentionally does not touch disk.
func (b *Bridge) VFSDeleteOnly(filePath string) error {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return fmt.Errorf("master bridge unavailable")
	}
	filePath = cleanBridgeVFSPath(filePath)
	if filePath == "/" {
		return fmt.Errorf("refusing to delete VFS root")
	}
	file := b.sm.GetVFS().GetFile(filePath)
	if file == nil {
		return fmt.Errorf("path not found in VFS: %s", filePath)
	}
	b.sm.GetVFS().DeleteFile(filePath)
	if b.raceDB != nil {
		if err := b.raceDB.DeletePath(cleanBridgeVFSPath(filePath), file.IsDir); err != nil {
			log.Printf("[Bridge] Race DB VFS-only delete sync failed for %s: %v", filePath, err)
		}
	}
	b.invalidateReadFileCache(filePath)
	b.sm.InvalidateReleaseStateForPath(filePath, file.IsDir)
	b.sm.SyncStatusMarkersForPath(filePath, file.IsDir)
	return nil
}

func (b *Bridge) ensureVFSParents(filePath, slaveName string) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return
	}
	parent := path.Dir(cleanBridgeVFSPath(filePath))
	if parent == "." || parent == "/" {
		return
	}
	parts := strings.Split(strings.Trim(parent, "/"), "/")
	current := ""
	now := time.Now().Unix()
	for _, part := range parts {
		if part == "" {
			continue
		}
		current += "/" + part
		if b.sm.GetVFS().GetFile(current) != nil {
			continue
		}
		b.sm.GetVFS().AddFile(current, VFSFile{
			Path:         current,
			IsDir:        true,
			Mode:         0755,
			LastModified: now,
			SlaveName:    slaveName,
			Owner:        "WeaveFTPd",
			Group:        "WeaveFTPd",
			Seen:         true,
		})
	}
}

func cleanBridgeVFSPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

func (b *Bridge) RelocatePath(from, toDir, toName string) error {
	return b.RelocatePathToSlave(from, toDir, toName, "")
}

func (b *Bridge) ScrubReleaseRaceMetadata(dirPath, owner, group string) error {
	if b == nil || b.sm == nil {
		return fmt.Errorf("master bridge unavailable")
	}
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	b.sm.GetVFS().ScrubReleaseRaceMetadata(cleanDirPath, owner, group)
	b.sm.ResetReleaseRaceWindow(cleanDirPath)
	if b.raceDB != nil {
		if err := b.raceDB.ScrubReleaseRaceMetadata(cleanDirPath, owner, group); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bridge) RelocatePathToSlave(from, toDir, toName, targetSlave string) error {
	file := b.sm.GetVFS().GetFile(from)
	if file == nil {
		return fmt.Errorf("path not found: %s", from)
	}
	if file.SlaveName == "" {
		return fmt.Errorf("path has no owning slave: %s", from)
	}
	rs := b.sm.GetSlave(file.SlaveName)
	if rs == nil || !rs.IsAvailable() {
		return fmt.Errorf("owning slave unavailable: %s", file.SlaveName)
	}
	toPath := cleanBridgeVFSPath(path.Join(toDir, toName))
	var destSlave *RemoteSlave
	if strings.TrimSpace(targetSlave) != "" {
		destSlave = b.sm.GetSlave(strings.TrimSpace(targetSlave))
		if destSlave == nil || !destSlave.IsAvailable() {
			return fmt.Errorf("requested destination slave unavailable: %s", strings.TrimSpace(targetSlave))
		}
		if b.sm.IsSlaveReadOnly(destSlave.Name()) {
			return fmt.Errorf("requested destination slave is read-only: %s", destSlave.Name())
		}
	} else {
		destSlave = b.sm.SelectSlaveForUpload(toPath)
	}
	if destSlave == nil || !destSlave.IsAvailable() {
		return fmt.Errorf("no available destination slave for %s", toPath)
	}
	if destSlave.Name() != rs.Name() {
		if err := b.relocateAcrossSlaves(file, rs, destSlave, from, toPath); err != nil {
			return err
		}
		b.sm.GetVFS().RelocateFile(from, toPath, destSlave.Name())
		if b.raceDB != nil {
			isDir := file.IsDir
			if err := b.raceDB.RenamePath(cleanBridgeVFSPath(from), cleanBridgeVFSPath(toPath), isDir); err != nil {
				log.Printf("[Bridge] Race DB rename sync failed %s -> %s: %v", from, toPath, err)
			}
		}
		b.sm.RenameReleaseState(from, toPath, file.IsDir)
		b.sm.SyncStatusMarkersForPath(from, file.IsDir)
		b.sm.SyncStatusMarkersForPath(toPath, file.IsDir)
		return nil
	}
	index, err := IssueRelocate(rs, from, toDir, toName)
	if err != nil {
		return err
	}
	resp, err := rs.FetchResponse(index, 30*time.Minute)
	if err != nil {
		return err
	}
	if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
		return fmt.Errorf("%s", errResp.Message)
	}
	b.sm.GetVFS().RenameFile(from, toPath)
	if b.raceDB != nil {
		isDir := file.IsDir
		if err := b.raceDB.RenamePath(cleanBridgeVFSPath(from), cleanBridgeVFSPath(toPath), isDir); err != nil {
			log.Printf("[Bridge] Race DB rename sync failed %s -> %s: %v", from, toPath, err)
		}
	}
	b.sm.RenameReleaseState(from, toPath, file.IsDir)
	b.sm.SyncStatusMarkersForPath(from, file.IsDir)
	b.sm.SyncStatusMarkersForPath(toPath, file.IsDir)
	return nil
}

func (b *Bridge) relocateAcrossSlaves(file *VFSFile, sourceSlave, destSlave *RemoteSlave, from, toPath string) error {
	if err := b.createDestDirsOnSlave(destSlave, file, from, toPath); err != nil {
		return err
	}

	filesToCopy := b.collectRelocateFiles(file, from, toPath)
	for _, item := range filesToCopy {
		if err := b.copyFileBetweenSlaves(sourceSlave, destSlave, item.from, item.to, item.owner, item.group, item.size); err != nil {
			_ = b.deletePathOnSlave(destSlave, toPath)
			return err
		}
	}

	if err := b.deletePathOnSlave(sourceSlave, from); err != nil {
		_ = b.deletePathOnSlave(destSlave, toPath)
		return err
	}
	return nil
}

type relocateFileItem struct {
	from  string
	to    string
	owner string
	group string
	size  int64
}

func (b *Bridge) createDestDirsOnSlave(destSlave *RemoteSlave, file *VFSFile, from, toPath string) error {
	if file == nil {
		return fmt.Errorf("nil relocate source")
	}
	if file.IsDir {
		if err := b.makeDirOnSlave(destSlave, toPath); err != nil {
			return err
		}
	}
	fromPrefix := strings.TrimRight(cleanBridgeVFSPath(from), "/") + "/"
	toPrefix := strings.TrimRight(cleanBridgeVFSPath(toPath), "/") + "/"
	for pathKey, vf := range b.sm.GetVFS().GetAllFiles() {
		if vf == nil || !vf.IsDir {
			continue
		}
		cleanPath := cleanBridgeVFSPath(pathKey)
		if !strings.HasPrefix(cleanPath, fromPrefix) {
			continue
		}
		rel := strings.TrimPrefix(cleanPath, fromPrefix)
		destDir := cleanBridgeVFSPath(toPrefix + rel)
		if err := b.makeDirOnSlave(destSlave, destDir); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bridge) collectRelocateFiles(file *VFSFile, from, toPath string) []relocateFileItem {
	items := []relocateFileItem{}
	addItem := func(src, dst string, vf *VFSFile) {
		if vf == nil || vf.IsDir {
			return
		}
		items = append(items, relocateFileItem{
			from:  cleanBridgeVFSPath(src),
			to:    cleanBridgeVFSPath(dst),
			owner: vf.Owner,
			group: vf.Group,
			size:  vf.Size,
		})
	}
	if file != nil && !file.IsDir {
		addItem(from, toPath, file)
		sort.Slice(items, func(i, j int) bool { return items[i].from < items[j].from })
		return items
	}

	fromPrefix := strings.TrimRight(cleanBridgeVFSPath(from), "/") + "/"
	toPrefix := strings.TrimRight(cleanBridgeVFSPath(toPath), "/") + "/"
	for pathKey, vf := range b.sm.GetVFS().GetAllFiles() {
		if vf == nil || vf.IsDir {
			continue
		}
		cleanPath := cleanBridgeVFSPath(pathKey)
		if !strings.HasPrefix(cleanPath, fromPrefix) {
			continue
		}
		rel := strings.TrimPrefix(cleanPath, fromPrefix)
		addItem(cleanPath, toPrefix+rel, vf)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].from < items[j].from })
	return items
}

func (b *Bridge) makeDirOnSlave(slave *RemoteSlave, dirPath string) error {
	index, err := IssueMakeDir(slave, dirPath)
	if err != nil {
		return fmt.Errorf("mkdir on %s failed: %w", slave.Name(), err)
	}
	if _, err := slave.FetchResponse(index, 30*time.Second); err != nil {
		return fmt.Errorf("mkdir on %s failed: %w", slave.Name(), err)
	}
	return nil
}

func (b *Bridge) writableAvailableSlaveByName(slaveName string) (*RemoteSlave, error) {
	if b == nil || b.sm == nil {
		return nil, fmt.Errorf("master not initialized")
	}
	name := strings.TrimSpace(slaveName)
	if name == "" {
		return nil, fmt.Errorf("slave name is empty")
	}
	slave := b.sm.GetSlave(name)
	if slave == nil || !slave.IsAvailable() {
		return nil, fmt.Errorf("requested slave unavailable: %s", name)
	}
	if b.sm.IsSlaveReadOnly(slave.Name()) {
		return nil, fmt.Errorf("requested slave is read-only: %s", slave.Name())
	}
	return slave, nil
}

func (b *Bridge) resolveOwningSlave(path string) (*RemoteSlave, *VFSFile, error) {
	if b == nil || b.sm == nil {
		return nil, nil, fmt.Errorf("master not initialized")
	}
	vfsPath := cleanBridgeVFSPath(path)
	file := b.sm.GetVFS().GetFile(vfsPath)
	if file == nil {
		return nil, nil, fmt.Errorf("path not found: %s", vfsPath)
	}
	if strings.TrimSpace(file.SlaveName) == "" {
		return nil, file, nil
	}
	if b.sm.IsSlaveReadOnly(file.SlaveName) {
		return nil, file, fmt.Errorf("path is on read-only slave: %s", vfsPath)
	}
	slave := b.sm.GetSlave(file.SlaveName)
	if slave == nil || !slave.IsAvailable() {
		return nil, file, fmt.Errorf("owning slave unavailable: %s", file.SlaveName)
	}
	return slave, file, nil
}

func (b *Bridge) selectWritableSlaveForCreate(filePath string) (*RemoteSlave, error) {
	if b == nil || b.sm == nil {
		return nil, fmt.Errorf("master not initialized")
	}
	vfsPath := cleanBridgeVFSPath(filePath)
	if slave, file, err := b.resolveOwningSlave(vfsPath); file != nil {
		if err != nil {
			return nil, err
		}
		if slave != nil && slaveCanStorePath(slave, vfsPath) {
			return slave, nil
		}
		if file.IsDir || file.IsSymlink {
			return nil, fmt.Errorf("path has no owning slave: %s", vfsPath)
		}
	}
	parent := cleanBridgeVFSPath(path.Dir(vfsPath))
	if parent != "." && parent != "/" {
		if slave, file, err := b.resolveOwningSlave(parent); file != nil {
			if err != nil {
				return nil, err
			}
			if slave != nil && slaveCanStorePath(slave, vfsPath) {
				return slave, nil
			}
			if !file.IsDir || file.IsSymlink {
				return nil, fmt.Errorf("parent path has no owning slave: %s", parent)
			}
		}
	}
	slave := b.sm.SelectSlaveForUpload(vfsPath)
	if slave == nil {
		return nil, fmt.Errorf("no available slave")
	}
	return slave, nil
}

func (b *Bridge) deletePathOnSlave(slave *RemoteSlave, filePath string) error {
	index, err := IssueDelete(slave, filePath)
	if err != nil {
		return fmt.Errorf("delete on %s failed: %w", slave.Name(), err)
	}
	if _, err := slave.FetchResponse(index, 5*time.Minute); err != nil {
		return fmt.Errorf("delete on %s failed: %w", slave.Name(), err)
	}
	return nil
}

func (b *Bridge) copyFileBetweenSlaves(sourceSlave, destSlave *RemoteSlave, fromPath, toPath, owner, group string, size int64) error {
	listenIdx, err := IssueListen(sourceSlave, false, false)
	if err != nil {
		return fmt.Errorf("source listen failed for %s: %w", fromPath, err)
	}
	listenResp, err := sourceSlave.FetchResponse(listenIdx, 60*time.Second)
	if err != nil {
		return fmt.Errorf("source listen failed for %s: %w", fromPath, err)
	}
	transferResp, ok := listenResp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return fmt.Errorf("unexpected source listen response for %s: %T", fromPath, listenResp)
	}

	remoteAddr := fmt.Sprintf("%s:%d", sourceSlave.GetPASVIP(), transferResp.Info.Port)
	connectIdx, err := IssueConnect(destSlave, sourceSlave.GetPASVIP(), transferResp.Info.Port, false, false)
	if err != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive connect failed")
		return fmt.Errorf("destination connect failed for %s: %w", toPath, err)
	}
	connectResp, err := destSlave.FetchResponse(connectIdx, 60*time.Second)
	if err != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive connect failed")
		return fmt.Errorf("destination connect failed for %s: %w", toPath, err)
	}
	destTransferResp, ok := connectResp.(*protocol.AsyncResponseTransfer)
	if !ok {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive connect failed")
		return fmt.Errorf("unexpected destination connect response for %s: %T", toPath, connectResp)
	}

	sendIdx, err := IssueSend(sourceSlave, fromPath, 'I', 0, remoteAddr, transferResp.Info.TransferIndex)
	if err != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive send setup failed")
		IssueAbort(destSlave, destTransferResp.Info.TransferIndex, "archive send setup failed")
		return fmt.Errorf("source send failed for %s: %w", fromPath, err)
	}
	recvIdx, err := IssueReceive(destSlave, toPath, 'I', 0, remoteAddr, destTransferResp.Info.TransferIndex)
	if err != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive receive setup failed")
		IssueAbort(destSlave, destTransferResp.Info.TransferIndex, "archive receive setup failed")
		return fmt.Errorf("destination receive failed for %s: %w", toPath, err)
	}
	if _, err := sourceSlave.FetchResponse(sendIdx, 60*time.Second); err != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive send ack failed")
		IssueAbort(destSlave, destTransferResp.Info.TransferIndex, "archive send ack failed")
		return fmt.Errorf("source send ack failed for %s: %w", fromPath, err)
	}
	if _, err := destSlave.FetchResponse(recvIdx, 60*time.Second); err != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive receive ack failed")
		IssueAbort(destSlave, destTransferResp.Info.TransferIndex, "archive receive ack failed")
		return fmt.Errorf("destination receive ack failed for %s: %w", toPath, err)
	}

	sourceStatus, sourceErr := sourceSlave.WaitTransferStatus(transferResp.Info.TransferIndex, 2*time.Hour)
	destStatus, destErr := destSlave.WaitTransferStatus(destTransferResp.Info.TransferIndex, 2*time.Hour)
	if sourceErr != nil {
		IssueAbort(destSlave, destTransferResp.Info.TransferIndex, "archive source transfer failed")
		return fmt.Errorf("source transfer failed for %s: %w", fromPath, sourceErr)
	}
	if destErr != nil {
		IssueAbort(sourceSlave, transferResp.Info.TransferIndex, "archive destination transfer failed")
		return fmt.Errorf("destination transfer failed for %s: %w", toPath, destErr)
	}
	if sourceStatus.Error != "" {
		return fmt.Errorf("source transfer error for %s: %s", fromPath, sourceStatus.Error)
	}
	if destStatus.Error != "" {
		return fmt.Errorf("destination transfer error for %s: %s", toPath, destStatus.Error)
	}
	destSize := finalUploadFileSize(destStatus, 0)
	if size > 0 && destSize != size {
		return fmt.Errorf("archive copy size mismatch for %s: expected %d got %d", toPath, size, destSize)
	}
	return nil
}

// MakeDir creates a directory on a selected slave and then records it in VFS.
func (b *Bridge) MakeDir(dirPath, owner, group string) error {
	var slave *RemoteSlave
	if parent := b.sm.GetVFS().GetFile(path.Dir(dirPath)); parent != nil && strings.TrimSpace(parent.SlaveName) != "" {
		slave = b.sm.GetSlave(parent.SlaveName)
		if slave != nil && (!slave.IsAvailable() || b.sm.IsSlaveReadOnly(slave.Name())) {
			slave = nil
		}
	}
	if slave == nil {
		slave = b.sm.SelectSlaveForUpload(dirPath)
	}
	if slave == nil {
		return fmt.Errorf("no available slave for mkdir: %s", dirPath)
	}
	if err := b.makeDirOnSlave(slave, dirPath); err != nil {
		return err
	}
	b.sm.MakeDirectoryOnSlave(dirPath, owner, group, slave.Name())
	b.sm.SyncStatusMarkersForPath(dirPath, true)
	return nil
}

func (b *Bridge) MakeDirOnSlave(dirPath, owner, group, slaveName string) error {
	if strings.TrimSpace(slaveName) == "" {
		return b.MakeDir(dirPath, owner, group)
	}
	slave, err := b.writableAvailableSlaveByName(slaveName)
	if err != nil {
		return err
	}
	dirPath = cleanBridgeVFSPath(dirPath)
	if err := b.makeDirOnSlave(slave, dirPath); err != nil {
		return err
	}
	b.sm.MakeDirectoryOnSlave(dirPath, owner, group, slave.Name())
	b.sm.SyncStatusMarkersForPath(dirPath, true)
	return nil
}

func (b *Bridge) Symlink(linkPath, targetPath string) error {
	linkPath = cleanBridgeVFSPath(linkPath)
	targetPath = cleanBridgeVFSPath(targetPath)
	targetResolved := b.ResolvePath(targetPath)

	slave, targetFile, err := b.resolveOwningSlave(targetResolved)
	if err != nil {
		return err
	}
	if targetFile == nil {
		return fmt.Errorf("symlink target not found: %s", targetPath)
	}
	if slave != nil {
		parentDir := cleanBridgeVFSPath(path.Dir(linkPath))
		if parentDir != "." && parentDir != "/" {
			if err := b.makeDirOnSlave(slave, parentDir); err != nil {
				return err
			}
		}
		targetArg := strings.TrimPrefix(cleanBridgeVFSPath(targetPath), "/")
		index, err := IssueSymlink(slave, linkPath, targetArg)
		if err != nil {
			return err
		}
		resp, err := slave.FetchResponse(index, 30*time.Second)
		if err != nil {
			return err
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			return fmt.Errorf("%s", errResp.Message)
		}
	}
	b.sm.GetVFS().AddSymlink(linkPath, targetPath)
	return nil
}

func (b *Bridge) VFSSymlink(linkPath, targetPath string) error {
	linkPath = cleanBridgeVFSPath(linkPath)
	targetPath = cleanBridgeVFSPath(targetPath)
	b.sm.GetVFS().AddSymlink(linkPath, targetPath)
	return nil
}

func (b *Bridge) SyncStatusMarkersForPath(filePath string, isDir bool) {
	if b == nil || b.sm == nil {
		return
	}
	b.sm.SyncStatusMarkersForPath(filePath, isDir)
}

func (b *Bridge) Chmod(path string, mode uint32) error {
	path = cleanBridgeVFSPath(path)
	slave, file, err := b.resolveOwningSlave(path)
	if err != nil {
		return err
	}
	if file == nil {
		return fmt.Errorf("path not found: %s", path)
	}
	if slave != nil {
		index, err := IssueChmod(slave, path, mode)
		if err != nil {
			return err
		}
		resp, err := slave.FetchResponse(index, 30*time.Second)
		if err != nil {
			return err
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			return fmt.Errorf("%s", errResp.Message)
		}
	}
	b.sm.GetVFS().Chmod(path, mode)
	return nil
}

// GetFileSize returns file size, or -1 if not found.
func (b *Bridge) GetFileSize(filePath string) int64 {
	f := b.sm.GetVFS().GetFile(filePath)
	if f == nil {
		if _, ok := b.pendingUploadForPath(filePath); ok {
			return 1
		}
		return -1
	}
	return f.Size
}

func (b *Bridge) GetPathEntry(filePath string) (core.MasterFileEntry, bool) {
	f := b.sm.GetVFS().GetFile(filePath)
	if f == nil {
		if pu, ok := b.pendingUploadForPath(filePath); ok {
			return pendingUploadEntry(pu), true
		}
		return core.MasterFileEntry{}, false
	}
	return masterEntryFromVFSFile(f), true
}

func (b *Bridge) ResolvePath(filePath string) string {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return cleanBridgeVFSPath(filePath)
	}
	return b.sm.GetVFS().ResolvePath(filePath)
}

// FileExists checks if a path exists in the VFS.
func (b *Bridge) FileExists(filePath string) bool {
	if b.sm.GetVFS().FileExists(filePath) {
		return true
	}
	_, ok := b.pendingUploadForPath(filePath)
	return ok
}

func (b *Bridge) PendingUploadExists(filePath string) bool {
	_, ok := b.pendingUploadForPath(filePath)
	return ok
}

func (b *Bridge) GetKnownChecksum(filePath string) (uint32, bool) {
	f := b.sm.GetVFS().GetFile(filePath)
	if f == nil || f.IsDir || f.Checksum == 0 {
		return 0, false
	}
	return f.Checksum, true
}

// ReadFile reads a small file from a slave (for .message/.imdb display).
func (b *Bridge) ReadFile(filePath string) ([]byte, error) {
	filePath = cleanBridgeVFSPath(filePath)
	b.cacheMu.Lock()
	if cached, ok := b.readFileCache[filePath]; ok && time.Now().Before(cached.expires) {
		content := append([]byte(nil), cached.content...)
		errText := cached.errText
		b.cacheMu.Unlock()
		if errText != "" {
			return nil, fmt.Errorf("%s", errText)
		}
		return content, nil
	}
	b.cacheMu.Unlock()

	readPath := filePath
	if resolved := b.ResolvePath(filePath); resolved != "" {
		readPath = resolved
	}
	vfsFile := b.sm.GetVFS().GetFile(readPath)
	if vfsFile == nil || vfsFile.IsDir {
		err := fmt.Errorf("file not found: %s", filePath)
		b.cacheReadFileResult(filePath, nil, err)
		return nil, err
	}

	candidates, candidateErr := b.candidateSlavesForPath(readPath)
	if candidateErr != nil {
		return nil, candidateErr
	}
	var lastErr error
	for _, slave := range candidates {
		index, err := IssueReadFile(slave, readPath)
		if err != nil {
			lastErr = fmt.Errorf("issue readFile to %s: %w", slave.Name(), err)
			continue
		}

		resp, err := slave.FetchResponse(index, 30*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", slave.Name(), err)
			continue
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			lastErr = fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
			continue
		}
		if fc, ok := resp.(*protocol.AsyncResponseFileContent); ok {
			b.cacheReadFileResult(filePath, fc.Content, nil)
			return fc.Content, nil
		}
		lastErr = fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
	}
	if lastErr != nil {
		b.cacheReadFileResult(filePath, nil, lastErr)
		return nil, lastErr
	}
	err := fmt.Errorf("file not found: %s", filePath)
	b.cacheReadFileResult(filePath, nil, err)
	return nil, err
}

func (b *Bridge) ReadZipEntry(archivePath, entryName string) ([]byte, error) {
	candidates, candidateErr := b.candidateSlavesForPath(archivePath)
	if candidateErr != nil {
		return nil, candidateErr
	}
	var lastErr error
	for _, slave := range candidates {
		index, err := IssueReadZipEntry(slave, archivePath, entryName)
		if err != nil {
			lastErr = fmt.Errorf("issue readZipEntry to %s: %w", slave.Name(), err)
			continue
		}

		resp, err := slave.FetchResponse(index, 30*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", slave.Name(), err)
			continue
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			lastErr = fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
			continue
		}
		if fc, ok := resp.(*protocol.AsyncResponseZipEntryContent); ok {
			return fc.Content, nil
		}
		lastErr = fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("file not found: %s", archivePath)
}

func (b *Bridge) CheckZipIntegrity(archivePath string) (bool, error) {
	candidates, candidateErr := b.candidateSlavesForPath(archivePath)
	if candidateErr != nil {
		return false, candidateErr
	}
	var lastErr error
	for _, slave := range candidates {
		index, err := IssueZipIntegrity(slave, archivePath)
		if err != nil {
			lastErr = fmt.Errorf("issue zipIntegrity to %s: %w", slave.Name(), err)
			continue
		}

		resp, err := slave.FetchResponse(index, 2*time.Minute)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", slave.Name(), err)
			continue
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			lastErr = fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
			continue
		}
		if zr, ok := resp.(*protocol.AsyncResponseZipIntegrity); ok {
			return zr.OK, nil
		}
		lastErr = fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
	}
	if lastErr != nil {
		return false, lastErr
	}
	return false, fmt.Errorf("file not found: %s", archivePath)
}

func (b *Bridge) ProbeMediaInfo(filePath, binary string, timeoutSeconds int) (map[string]string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 20
	}
	candidates, candidateErr := b.candidateSlavesForPath(filePath)
	if candidateErr != nil {
		return nil, candidateErr
	}
	var lastErr error
	for _, slave := range candidates {
		index, err := IssueMediaInfo(slave, filePath, binary, timeoutSeconds)
		if err != nil {
			lastErr = fmt.Errorf("issue media probe to %s: %w", slave.Name(), err)
			continue
		}
		resp, err := slave.FetchResponse(index, time.Duration(timeoutSeconds+5)*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", slave.Name(), err)
			continue
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			lastErr = fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
			continue
		}
		if mi, ok := resp.(*protocol.AsyncResponseMediaInfo); ok {
			return mi.Fields, nil
		}
		lastErr = fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("file not found: %s", filePath)
}

// GetSFVInfo asks a slave to parse an SFV file and return the entries.
func (b *Bridge) GetSFVInfo(sfvPath string) (core.SFVInfo, error) {
	candidates, candidateErr := b.candidateSlavesForPath(sfvPath)
	if candidateErr != nil {
		return core.SFVInfo{}, candidateErr
	}
	var lastErr error
	for _, slave := range candidates {
		index, err := IssueSFVFile(slave, sfvPath)
		if err != nil {
			lastErr = fmt.Errorf("issue sfvFile to %s: %w", slave.Name(), err)
			continue
		}

		resp, err := slave.FetchResponse(index, 30*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", slave.Name(), err)
			continue
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			lastErr = fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
			continue
		}

		if sfv, ok := resp.(*protocol.AsyncResponseSFVInfo); ok {
			entries := make([]core.SFVEntryInfo, len(sfv.Entries))
			for i, e := range sfv.Entries {
				entries[i] = core.SFVEntryInfo{FileName: e.FileName, CRC32: e.CRC32}
			}
			return core.SFVInfo{Entries: entries, Checksum: sfv.Checksum, Size: sfv.Size}, nil
		}

		lastErr = fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
	}
	if lastErr != nil {
		return core.SFVInfo{}, lastErr
	}
	return core.SFVInfo{}, fmt.Errorf("sfv not found: %s", sfvPath)
}

// WriteFile writes a small file to a slave.
func (b *Bridge) WriteFile(filePath string, content []byte) error {
	filePath = cleanBridgeVFSPath(filePath)
	slave, err := b.selectWritableSlaveForCreate(filePath)
	if err != nil {
		return err
	}
	return b.writeFileOnSlave(filePath, content, slave)
}

func (b *Bridge) WriteFileOnSlave(filePath string, content []byte, slaveName string) error {
	if strings.TrimSpace(slaveName) == "" {
		return b.WriteFile(filePath, content)
	}
	filePath = cleanBridgeVFSPath(filePath)
	slave, err := b.writableAvailableSlaveByName(slaveName)
	if err != nil {
		return err
	}
	return b.writeFileOnSlave(filePath, content, slave)
}

func (b *Bridge) writeFileOnSlave(filePath string, content []byte, slave *RemoteSlave) error {
	index, err := IssueWriteFile(slave, filePath, string(content))
	if err != nil {
		return fmt.Errorf("issue writeFile: %w", err)
	}

	resp, err := slave.FetchResponse(index, 30*time.Second)
	if err != nil {
		return err
	}
	if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
		return fmt.Errorf("%s", errResp.Message)
	}

	// Add to VFS
	b.sm.GetVFS().AddFile(filePath, VFSFile{
		Path:         filePath,
		Size:         int64(len(content)),
		IsDir:        false,
		LastModified: time.Now().Unix(),
		SlaveName:    slave.Name(),
		Checksum:     crc32.ChecksumIEEE(content),
	})
	b.cacheReadFileResult(filePath, content, nil)
	b.sm.SyncStatusMarkersForPath(filePath, false)

	return nil
}

func (b *Bridge) cacheReadFileResult(filePath string, content []byte, err error) {
	if b == nil {
		return
	}
	cached := cachedReadFileResult{
		content: append([]byte(nil), content...),
		expires: time.Now().Add(readFileCacheTTL),
	}
	if err != nil {
		cached.errText = err.Error()
	}
	b.cacheMu.Lock()
	if b.readFileCache == nil {
		b.readFileCache = make(map[string]cachedReadFileResult)
	}
	b.readFileCache[filePath] = cached
	b.cacheMu.Unlock()
}

func (b *Bridge) invalidateReadFileCache(filePath string) {
	if b == nil {
		return
	}
	filePath = cleanBridgeVFSPath(filePath)
	b.cacheMu.Lock()
	delete(b.readFileCache, filePath)
	b.cacheMu.Unlock()
}

func (b *Bridge) CreateSparseFile(filePath string, size int64, owner, group string) error {
	if size < 0 {
		return fmt.Errorf("invalid sparse file size: %d", size)
	}
	filePath = cleanBridgeVFSPath(filePath)
	slave, err := b.selectWritableSlaveForCreate(filePath)
	if err != nil {
		return err
	}

	index, err := IssueCreateSparseFile(slave, filePath, size)
	if err != nil {
		return fmt.Errorf("issue createSparseFile: %w", err)
	}
	resp, err := slave.FetchResponse(index, 30*time.Second)
	if err != nil {
		return err
	}
	if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
		return fmt.Errorf("%s", errResp.Message)
	}

	b.sm.GetVFS().AddFile(filePath, VFSFile{
		Path:         filePath,
		Size:         size,
		IsDir:        false,
		LastModified: time.Now().Unix(),
		SlaveName:    slave.Name(),
		Owner:        owner,
		Group:        group,
	})
	b.sm.SyncStatusMarkersForPath(filePath, false)
	return nil
}

func (b *Bridge) ChecksumFile(filePath string) (uint32, error) {
	candidates, candidateErr := b.candidateSlavesForPath(filePath)
	if candidateErr != nil {
		return 0, candidateErr
	}
	var lastErr error
	for _, slave := range candidates {
		index, err := IssueChecksum(slave, filePath)
		if err != nil {
			lastErr = fmt.Errorf("issue checksum to %s: %w", slave.Name(), err)
			continue
		}
		resp, err := slave.FetchResponse(index, 10*time.Minute)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", slave.Name(), err)
			continue
		}
		if errResp, ok := resp.(*protocol.AsyncResponseError); ok {
			lastErr = fmt.Errorf("%s: %s", slave.Name(), errResp.Message)
			continue
		}
		if checksum, ok := resp.(*protocol.AsyncResponseChecksum); ok {
			return checksum.Checksum, nil
		}
		lastErr = fmt.Errorf("%s: unexpected response type: %T", slave.Name(), resp)
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("file not found: %s", filePath)
}

func (b *Bridge) candidateSlavesForPath(filePath string) ([]*RemoteSlave, error) {
	cleanPath := cleanBridgeVFSPath(filePath)
	pathsToCheck := []string{cleanPath}
	if resolved := b.ResolvePath(cleanPath); resolved != "" && resolved != cleanPath {
		pathsToCheck = append(pathsToCheck, resolved)
	}
	for _, candidatePath := range pathsToCheck {
		slave, file, err := b.resolveOwningSlave(candidatePath)
		if file == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		if slave != nil {
			return []*RemoteSlave{slave}, nil
		}
		return nil, fmt.Errorf("path has no owning slave: %s", cleanPath)
	}

	out := make([]*RemoteSlave, 0, 1)
	seen := map[string]bool{}
	for _, slave := range b.sm.GetAvailableSlaves() {
		if slave == nil || seen[slave.Name()] {
			continue
		}
		out = append(out, slave)
		seen[slave.Name()] = true
	}
	return out, nil
}

func (b *Bridge) MarkFileMissing(filePath string) error {
	b.sm.GetVFS().DeleteFile(filePath)
	var err error
	if b.raceDB != nil {
		err = b.raceDB.DeletePath(cleanBridgeVFSPath(filePath), false)
	}
	b.sm.InvalidateReleaseStateForPath(filePath, false)
	b.sm.SyncStatusMarkersForPath(filePath, false)
	return err
}

func (b *Bridge) reconcileFailedUploadState(filePath string, slave *RemoteSlave) {
	if b == nil || slave == nil {
		return
	}
	index, err := IssueChecksum(slave, filePath)
	if err != nil {
		return
	}
	resp, err := slave.FetchResponse(index, 30*time.Second)
	if err != nil {
		return
	}
	if _, ok := resp.(*protocol.AsyncResponseChecksum); ok {
		return
	}
	if errResp, ok := resp.(*protocol.AsyncResponseError); ok && isDefinitiveMissingResponse(errResp.Message) {
		_ = b.MarkFileMissing(filePath)
	}
}

func (b *Bridge) reconcileUnavailableDownloadState(filePath string, slave *RemoteSlave) {
	if b == nil || slave == nil {
		return
	}
	index, err := IssueChecksum(slave, filePath)
	if err != nil {
		return
	}
	resp, err := slave.FetchResponse(index, 30*time.Second)
	if err != nil {
		return
	}
	if _, ok := resp.(*protocol.AsyncResponseChecksum); ok {
		return
	}
	if errResp, ok := resp.(*protocol.AsyncResponseError); ok && isDefinitiveMissingResponse(errResp.Message) {
		_ = b.MarkFileMissing(filePath)
	}
}

func isDefinitiveMissingResponse(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(lower, "file not found")
}

func (b *Bridge) SyncPresentFile(filePath string, checksum uint32) error {
	f := b.sm.GetVFS().GetFile(filePath)
	if f == nil || f.IsDir {
		return fmt.Errorf("file not found: %s", filePath)
	}
	b.sm.GetVFS().UpdateFileVerification(filePath, checksum)
	if b.raceDB != nil {
		dirPath := path.Dir(filePath)
		meta := b.sm.GetVFS().GetSFVData(dirPath)
		if meta != nil && len(meta.SFVEntries) > 0 {
			if verified := b.sm.GetVFS().GetVerifiedSFVPresentFilesFiltered(dirPath, b.liveUploadingRaceKeysForDir(cleanBridgeVFSPath(dirPath))); len(verified) == len(meta.SFVEntries) {
				return b.SyncReleaseRaceStats(dirPath)
			}
		}
	}
	return nil
}

// =====================================================================
// VFS ADAPTER FOR PLUGINS (Implements zipscript.FileSystem implicitly)
// =====================================================================

func (b *Bridge) PluginFS() *VFSAdapter {
	return &VFSAdapter{b: b}
}

type VFSAdapter struct {
	b *Bridge
}

func (v *VFSAdapter) ReadDir(dirPath string) ([]os.DirEntry, error) {
	entries := v.b.ListDir(dirPath)
	var result []os.DirEntry
	for _, e := range entries {
		result = append(result, vfsDirEntry{
			info: vfsFileInfo{
				name:    e.Name,
				size:    e.Size,
				isDir:   e.IsDir,
				modTime: time.Unix(e.ModTime, 0),
			},
		})
	}
	return result, nil
}

func (v *VFSAdapter) ReadFile(filePath string) ([]byte, error) {
	return v.b.ReadFile(filePath)
}

func (v *VFSAdapter) Stat(filePath string) (os.FileInfo, error) {
	f := v.b.sm.GetVFS().GetFile(filePath)
	if f == nil {
		return nil, os.ErrNotExist
	}
	return vfsFileInfo{
		name:    path.Base(f.Path),
		size:    f.Size,
		isDir:   f.IsDir,
		modTime: time.Unix(f.LastModified, 0),
	}, nil
}

func (v *VFSAdapter) WriteFile(filePath string, data []byte, perm os.FileMode) error {
	return v.b.WriteFile(filePath, data)
}

func (v *VFSAdapter) Remove(filePath string) error {
	return v.b.DeleteFile(filePath)
}

func (v *VFSAdapter) RemoveAll(filePath string) error {
	return v.b.DeleteFile(filePath)
}

func (v *VFSAdapter) MkdirAll(dirPath string, perm os.FileMode) error {
	parentDir := path.Dir(dirPath)
	owner := "WeaveFTPd"
	group := "WeaveFTPd"

	// Inherit owner/group from the parent directory (e.g., the Release folder)
	parentFile := v.b.sm.GetVFS().GetFile(parentDir)
	if parentFile != nil {
		if parentFile.Owner != "" {
			owner = parentFile.Owner
			group = parentFile.Group
		}
	}

	// Triggers VFS creation AND network broadcast to the slave
	return v.b.MakeDir(dirPath, owner, group)
}

func (v *VFSAdapter) Symlink(oldname, newname string) error {
	return v.b.Symlink(newname, oldname)
}

// --- Virtual File Info & DirEntry Structs ---

type vfsFileInfo struct {
	name    string
	size    int64
	isDir   bool
	modTime time.Time
}

func (f vfsFileInfo) Name() string { return f.name }
func (f vfsFileInfo) Size() int64  { return f.size }
func (f vfsFileInfo) Mode() os.FileMode {
	if f.isDir {
		return os.ModeDir | 0755
	}
	return 0644
}
func (f vfsFileInfo) ModTime() time.Time { return f.modTime }
func (f vfsFileInfo) IsDir() bool        { return f.isDir }
func (f vfsFileInfo) Sys() any           { return nil }

type vfsDirEntry struct {
	info vfsFileInfo
}

func (d vfsDirEntry) Name() string               { return d.info.name }
func (d vfsDirEntry) IsDir() bool                { return d.info.isDir }
func (d vfsDirEntry) Type() os.FileMode          { return d.info.Mode().Type() }
func (d vfsDirEntry) Info() (os.FileInfo, error) { return d.info, nil }

// CacheSFV stores parsed SFV entries on the VFS directory and persists them.
func (b *Bridge) CacheSFV(dirPath string, sfvName string, info core.SFVInfo) {
	sfvMap := make(map[string]uint32, len(info.Entries))
	for _, e := range info.Entries {
		sfvMap[e.FileName] = e.CRC32
	}
	b.sm.GetVFS().SetSFVDataWithChecksum(dirPath, sfvName, info.Checksum, sfvMap)
	if info.Size > 0 || info.Checksum != 0 {
		sfvPath := path.Join(dirPath, sfvName)
		if b.sm.GetVFS().HydrateRaceFile(sfvPath, "", "", info.Size, 0, info.Checksum) {
			b.invalidateReadFileCache(sfvPath)
		}
	}
	if b.raceDB != nil {
		if err := b.raceDB.SaveSFV(cleanBridgeVFSPath(dirPath), sfvName, sfvMap); err != nil {
			log.Printf("[Bridge] Race DB SFV sync failed for %s: %v", dirPath, err)
		}
	}
	log.Printf("[Bridge] Cached SFV for %s: %d entries", dirPath, len(info.Entries))
}

func (b *Bridge) CacheMediaInfo(dirPath string, fields map[string]string) {
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	b.sm.SetReleaseMediaInfo(cleanDirPath, fields)
	if b.raceDB != nil {
		if err := b.raceDB.SaveMediaInfo(cleanDirPath, fields); err != nil {
			log.Printf("[Bridge] Race DB media probe sync failed for %s: %v", cleanDirPath, err)
		}
	}
}

func (b *Bridge) ClaimReleaseMetadataAnnouncement(dirPath, key string) bool {
	return b.sm.ClaimReleaseAnnouncement(dirPath, key)
}

// GetVFSRaceStats returns race statistics for a directory,
// counting ONLY files that are listed in the cached SFV data.
func (b *Bridge) GetVFSRaceStats(dirPath string) ([]core.VFSRaceUser, []core.VFSRaceGroup, int64, int, int) {
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	excludeKeys := b.liveUploadingRaceKeysForDir(cleanDirPath)
	users, groups, totalBytes, present, total := b.sm.GetVFS().GetRaceStatsFiltered(dirPath, excludeKeys)
	return convertRaceStats(users, groups, totalBytes, present, total)
}

// GetVFSReleaseStats returns the canonical release stats for PRE-like consumers.
// SFV metadata remains authoritative; ZIP-only dirs fall back to observed ZIP payloads.
func (b *Bridge) GetVFSReleaseStats(dirPath string) ([]core.VFSRaceUser, []core.VFSRaceGroup, int64, int, int) {
	coreUsers, coreGroups, totalBytes, present, total := b.GetVFSRaceStats(dirPath)
	if hasCoreRaceStats(coreUsers, coreGroups, totalBytes, present, total) {
		return coreUsers, coreGroups, totalBytes, present, total
	}

	cleanDirPath := cleanBridgeVFSPath(dirPath)
	excludeKeys := b.liveUploadingRaceKeysForDir(cleanDirPath)
	users, groups, totalBytes, present, total := b.sm.GetVFS().GetZipRaceStatsFiltered(dirPath, excludeKeys)
	return convertRaceStats(users, groups, totalBytes, present, total)
}

func hasCoreRaceStats(users []core.VFSRaceUser, groups []core.VFSRaceGroup, totalBytes int64, present int, total int) bool {
	return len(users) > 0 || len(groups) > 0 || totalBytes > 0 || present > 0 || total > 0
}

func convertRaceStats(users []RaceUserStat, groups []RaceGroupStat, totalBytes int64, present int, total int) ([]core.VFSRaceUser, []core.VFSRaceGroup, int64, int, int) {
	coreUsers := make([]core.VFSRaceUser, len(users))
	for i, u := range users {
		coreUsers[i] = core.VFSRaceUser{
			Name:       u.Name,
			Group:      u.Group,
			Files:      u.Files,
			Bytes:      u.Bytes,
			Speed:      u.Speed,
			PeakSpeed:  u.PeakSpeed,
			SlowSpeed:  u.SlowSpeed,
			Percent:    u.Percent,
			DurationMs: u.DurationMs,
		}
	}
	coreGroups := make([]core.VFSRaceGroup, len(groups))
	for i, g := range groups {
		coreGroups[i] = core.VFSRaceGroup{
			Name:    g.Name,
			Files:   g.Files,
			Bytes:   g.Bytes,
			Speed:   g.Speed,
			Percent: g.Percent,
		}
	}

	return coreUsers, coreGroups, totalBytes, present, total
}

func (b *Bridge) GetVFSRaceStatsFresh(dirPath string) ([]core.VFSRaceUser, []core.VFSRaceGroup, int64, int, int) {
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	excludeKeys := b.liveUploadingRaceKeysForDirFresh(cleanDirPath)
	users, groups, totalBytes, present, total := b.sm.GetVFS().GetRaceStatsFiltered(dirPath, excludeKeys)
	return convertRaceStats(users, groups, totalBytes, present, total)
}

func (b *Bridge) PluginGetVFSRaceStats(dirPath string) ([]plugin.RaceUser, []plugin.RaceGroup, int64, int, int) {
	coreUsers, coreGroups, totalBytes, present, total := b.GetVFSRaceStats(dirPath)
	users, groups := pluginRaceStatsFromCore(coreUsers, coreGroups)
	return users, groups, totalBytes, present, total
}

func (b *Bridge) PluginGetVFSReleaseStats(dirPath string) ([]plugin.RaceUser, []plugin.RaceGroup, int64, int, int) {
	coreUsers, coreGroups, totalBytes, present, total := b.GetVFSReleaseStats(dirPath)
	users, groups := pluginRaceStatsFromCore(coreUsers, coreGroups)
	return users, groups, totalBytes, present, total
}

func pluginRaceStatsFromCore(coreUsers []core.VFSRaceUser, coreGroups []core.VFSRaceGroup) ([]plugin.RaceUser, []plugin.RaceGroup) {
	users := make([]plugin.RaceUser, 0, len(coreUsers))
	for _, u := range coreUsers {
		users = append(users, plugin.RaceUser{
			Name:    u.Name,
			Group:   u.Group,
			Files:   u.Files,
			Bytes:   u.Bytes,
			Speed:   u.Speed,
			Percent: u.Percent,
		})
	}
	groups := make([]plugin.RaceGroup, 0, len(coreGroups))
	for _, g := range coreGroups {
		groups = append(groups, plugin.RaceGroup{
			Name:    g.Name,
			Files:   g.Files,
			Bytes:   g.Bytes,
			Speed:   g.Speed,
			Percent: g.Percent,
		})
	}
	return users, groups
}

// GetRaceWallClockMilliseconds returns wall-clock race duration (first file
// start to last file end) in milliseconds. 0 if race db unavailable or dir
// unknown.
func (b *Bridge) GetRaceWallClockMilliseconds(dirPath string) int64 {
	return b.sm.GetReleaseRaceWindowMilliseconds(cleanBridgeVFSPath(dirPath))
}

func (b *Bridge) StartReleaseRaceWindow(dirPath string, startMs int64) {
	if b == nil || b.sm == nil {
		return
	}
	b.sm.StartReleaseRaceWindowAt(cleanBridgeVFSPath(dirPath), startMs)
}

func (b *Bridge) NoteRacePayloadTransfer(dirPath, fileName string, durationMs int64) {
	b.NoteRacePayloadTransferAt(dirPath, fileName, durationMs, 0)
}

func (b *Bridge) NoteRacePayloadTransferAt(dirPath, fileName string, durationMs int64, endMs int64) {
	// Only real release files seed the race window. cbftp uploads the .sfv (and
	// often the .nfo) first, sometimes many seconds before the actual data files
	// start flowing; counting them would stretch the window across that dead air
	// and inflate the announced duration. pzs-ng and drftpd both time from the
	// first DATA file, not the SFV; match that.
	lname := strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(fileName, "\\", "/"))))
	if strings.HasSuffix(lname, ".sfv") || strings.HasSuffix(lname, ".nfo") {
		return
	}
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	if endMs <= 0 && b != nil && b.sm != nil {
		if f := b.sm.GetVFS().GetFile(path.Join(cleanDirPath, fileName)); f != nil && f.LastModified > 0 {
			endMs = f.LastModified * 1000
		}
	}
	b.sm.NoteRacePayloadTransferAt(cleanDirPath, durationMs, endMs)
}

func (b *Bridge) SyncReleaseRaceStats(dirPath string) error {
	if b == nil || b.raceDB == nil || b.sm == nil {
		return nil
	}
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	meta := b.sm.GetVFS().GetSFVData(cleanDirPath)
	if meta == nil || len(meta.SFVEntries) == 0 {
		return nil
	}

	verified := b.sm.GetVFS().GetVerifiedSFVPresentFilesFiltered(cleanDirPath, b.liveUploadingRaceKeysForDir(cleanDirPath))
	if len(verified) == 0 {
		return nil
	}

	files := make(map[string]ReleaseFileRecord, len(verified))
	for _, entry := range b.ListDir(cleanDirPath) {
		if entry.IsDir {
			continue
		}
		key := raceDBFileKey(entry.Name)
		if !verified[key] {
			continue
		}
		f := b.sm.GetVFS().GetFile(path.Join(cleanDirPath, entry.Name))
		if f == nil || f.IsDir {
			continue
		}
		files[key] = ReleaseFileRecord{
			FileName:   key,
			Owner:      f.Owner,
			Group:      f.Group,
			SizeBytes:  f.Size,
			DurationMs: f.XferTime,
			Checksum:   f.Checksum,
		}
	}
	return b.raceDB.ReplaceReleaseFiles(cleanDirPath, meta.SFVName, meta.SFVEntries, files)
}

// GetSFVData returns cached SFV entries for a directory.
func (b *Bridge) GetSFVData(dirPath string) map[string]uint32 {
	meta := b.sm.GetVFS().GetSFVData(dirPath)
	if meta == nil {
		return nil
	}
	return meta.SFVEntries
}

func (b *Bridge) GetReleaseStatus(dirPath string) (core.ReleaseStatus, bool) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return core.ReleaseStatus{}, false
	}
	return b.sm.GetVFS().GetReleaseStatus(dirPath)
}

func (b *Bridge) GetZipExpectedParts(dirPath string) (int, bool) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return 0, false
	}
	return b.sm.GetVFS().GetZipExpectedParts(dirPath)
}

func (b *Bridge) CacheZipExpectedParts(dirPath string, expected int, dizChecksum uint32) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return
	}
	b.sm.GetVFS().CacheZipExpectedParts(dirPath, expected, dizChecksum)
}

func (b *Bridge) GetRequestData(dirPath string) ([]plugin.RequestRecord, []plugin.RequestFillRecord) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return nil, nil
	}
	return b.sm.GetVFS().GetRequestData(dirPath)
}

func (b *Bridge) SetRequestData(dirPath string, requests []plugin.RequestRecord, fills []plugin.RequestFillRecord) {
	if b == nil || b.sm == nil || b.sm.GetVFS() == nil {
		return
	}
	vfs := b.sm.GetVFS()
	vfs.SetRequestData(dirPath, requests, fills)
	if b.sm.running.Load() {
		if err := vfs.SaveToDisk(vfsFilePath); err != nil {
			log.Printf("[Bridge] Error saving request metadata for %s: %v", dirPath, err)
		}
	}
}

func (b *Bridge) GetVerifiedSFVPresentFiles(dirPath string) map[string]bool {
	if b == nil || b.sm == nil {
		return nil
	}
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	return b.sm.GetVFS().GetVerifiedSFVPresentFilesFiltered(cleanDirPath, b.liveUploadingRaceKeysForDir(cleanDirPath))
}

func (b *Bridge) liveUploadingRaceKeysForDir(dirPath string) map[string]bool {
	byDir := b.liveUploadingRaceKeysByDir(cleanBridgeVFSPath(dirPath), true)
	return byDir[cleanBridgeVFSPath(dirPath)]
}

func (b *Bridge) liveUploadingRaceKeysForDirFresh(dirPath string) map[string]bool {
	byDir := b.liveUploadingRaceKeysByDir(cleanBridgeVFSPath(dirPath), false)
	return byDir[cleanBridgeVFSPath(dirPath)]
}

func (b *Bridge) liveUploadingRaceKeysByDir(rootDir string, useCache bool) map[string]map[string]bool {
	if b == nil {
		return nil
	}
	rootDir = cleanBridgeVFSPath(rootDir)
	rootPrefix := strings.TrimRight(cleanBridgeVFSPath(rootDir), "/") + "/"
	out := make(map[string]map[string]bool)
	for _, stat := range b.getLiveTransferStats(useCache) {
		if stat.Direction != "upload" {
			continue
		}
		cleanPath := cleanBridgeVFSPath(stat.Path)
		parentDir := cleanBridgeVFSPath(path.Dir(cleanPath))
		parentSlash := cleanBridgeVFSPath(parentDir)
		if parentDir != rootDir && !strings.HasPrefix(parentSlash+"/", rootPrefix) {
			continue
		}
		key := raceFileKey(path.Base(cleanPath))
		if out[parentDir] == nil {
			out[parentDir] = make(map[string]bool)
		}
		out[parentDir][key] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (b *Bridge) GetDirMediaInfo(dirPath string) map[string]string {
	cleanDirPath := cleanBridgeVFSPath(dirPath)
	if cached := b.sm.GetReleaseMediaInfo(cleanDirPath); len(cached) > 0 {
		return cached
	}
	if b.raceDB == nil {
		return nil
	}
	fields := b.raceDB.GetMediaInfo(cleanDirPath)
	if len(fields) == 0 {
		return nil
	}
	b.sm.SetReleaseMediaInfo(cleanDirPath, fields)
	return fields
}

func (b *Bridge) SearchDirs(query string, limit int) []core.VFSSearchResult {
	if b.raceDB != nil {
		if results := b.raceDB.SearchDirs(query, limit); len(results) > 0 {
			return results
		}
	}
	vfsResults := b.sm.GetVFS().SearchDirs(query, limit)
	results := make([]core.VFSSearchResult, 0, len(vfsResults))
	for _, r := range vfsResults {
		results = append(results, core.VFSSearchResult{
			Path:    r.Path,
			Files:   r.Files,
			Bytes:   r.Bytes,
			ModTime: r.ModTime,
		})
	}
	return results
}

// SlaveListenForPassthrough asks a slave to open a listener for direct client connection.
// uploadPath may be empty if the eventual upload path is not yet known (pure PASV);
// pass it when possible so section-affinity routing picks the right slave.
// Returns the slave's public IP, the port it's listening on, and the transfer index.
func (b *Bridge) SlaveListenForPassthrough(uploadPath string, encrypted bool, sslClientMode bool) (string, int, int32, string, error) {
	slave := b.sm.SelectSlaveForUpload(uploadPath)
	if slave == nil {
		return "", 0, 0, "", fmt.Errorf("no available slave")
	}

	listenIdx, err := IssueListen(slave, encrypted, sslClientMode)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("issue listen to %s: %w", slave.Name(), err)
	}

	resp, err := slave.FetchResponse(listenIdx, 60*time.Second)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("slave %s listen failed: %w", slave.Name(), err)
	}

	transferResp, ok := resp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("unexpected response from slave")
	}

	return slave.GetPASVIP(), transferResp.Info.Port, transferResp.Info.TransferIndex, slave.Name(), nil
}

// SlaveListenForDownloadPassthrough asks the slave that owns filePath to open
// a listener for direct client download.
func (b *Bridge) SlaveListenForDownloadPassthrough(filePath string, encrypted bool, sslClientMode bool) (string, int, int32, string, error) {
	slave := b.selectSlaveForDownloadIncludingPending(filePath)
	if slave == nil {
		return "", 0, 0, "", fmt.Errorf("file not found on any available slave: %s", filePath)
	}

	listenIdx, err := IssueListen(slave, encrypted, sslClientMode)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("issue listen to %s: %w", slave.Name(), err)
	}

	resp, err := slave.FetchResponse(listenIdx, 60*time.Second)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("slave %s listen failed: %w", slave.Name(), err)
	}

	transferResp, ok := resp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return "", 0, 0, "", fmt.Errorf("unexpected response from slave")
	}

	return slave.GetPASVIP(), transferResp.Info.Port, transferResp.Info.TransferIndex, slave.Name(), nil
}

// SlaveReceivePassthrough tells a slave to receive a file (client already connected directly).
// Waits for the slave to finish and returns size, checksum, duration.
func (b *Bridge) SlaveReceivePassthrough(filePath string, transferIdx int32, slaveName string, owner, group string, position int64, transferType byte) (int64, uint32, int64, error) {
	slave := b.sm.GetSlave(slaveName)
	if slave == nil {
		return 0, 0, 0, fmt.Errorf("slave %s not found", slaveName)
	}

	slave.IncActiveTransfers()
	defer slave.DecActiveTransfers()

	recvIdx, err := IssueReceive(slave, filePath, transferType, position, "master", transferIdx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("issue receive: %w", err)
	}

	// Wait for receive ACK
	_, err = slave.FetchResponse(recvIdx, 60*time.Second)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("receive ack: %w", err)
	}
	b.notePendingUpload(filePath, slaveName, owner, group, position)
	defer b.clearPendingUpload(filePath)

	// Wait for transfer to complete — poll the RemoteTransfer status
	status, err := slave.WaitTransferStatus(transferIdx, 2*time.Hour)
	if err != nil {
		b.reconcileFailedUploadState(filePath, slave)
		return 0, 0, 0, err
	}
	if status.Error != "" {
		b.reconcileFailedUploadState(filePath, slave)
		return status.Transferred, status.Checksum, status.Elapsed, fmt.Errorf("%s", status.Error)
	}

	finalSize := finalUploadFileSize(status, position)
	finalChecksum := status.Checksum
	if position > 0 {
		if checksum, err := b.ChecksumFile(filePath); err == nil {
			finalChecksum = checksum
		}
	}

	b.sm.GetVFS().AddFile(filePath, VFSFile{
		Path:         filePath,
		Size:         finalSize,
		IsDir:        false,
		LastModified: time.Now().Unix(),
		SlaveName:    slaveName,
		Owner:        owner,
		Group:        group,
		XferTime:     status.Elapsed,
		Checksum:     finalChecksum,
		Seen:         true,
	})
	b.recordUploadMetadata(filePath, owner, group, finalSize, status.Elapsed, finalChecksum)
	b.sm.SyncStatusMarkersForPath(filePath, false)

	log.Printf("[Passthrough] Upload %s on %s (%d bytes, %dms, CRC=%08X)",
		filePath, slaveName, finalSize, status.Elapsed, finalChecksum)

	return finalSize, finalChecksum, status.Elapsed, nil
}

// SlaveSendPassthrough tells a slave to send a file (client already connected directly).
func (b *Bridge) SlaveSendPassthrough(filePath string, transferIdx int32, slaveName string, username, primaryGroup string, position int64, transferType byte) (uint32, int64, error) {
	slave := b.sm.GetSlave(slaveName)
	if slave == nil {
		return 0, 0, fmt.Errorf("slave %s not found", slaveName)
	}

	slave.IncActiveTransfers()
	defer slave.DecActiveTransfers()

	sendIdx, err := IssueSend(slave, filePath, transferType, position, "master", transferIdx)
	if err != nil {
		return 0, 0, fmt.Errorf("issue send: %w", err)
	}

	_, err = slave.FetchResponse(sendIdx, 60*time.Second)
	if err != nil {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, 0, fmt.Errorf("send ack: %w", err)
	}

	status, err := slave.WaitTransferStatus(transferIdx, 2*time.Hour)
	if err != nil {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, 0, err
	}
	if status.Error != "" {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, 0, fmt.Errorf("%s", status.Error)
	}

	if position > 0 {
		return 0, status.Elapsed, nil
	}
	b.repairDownloadedFileSize(filePath, status.Transferred)
	return status.Checksum, status.Elapsed, nil
}

// SlaveConnectAndReceive tells a slave to connect out to a remote address (PORT mode passthrough)
// and receive a file. The slave connects directly to the remote site — master doesn't touch the data.
func (b *Bridge) SlaveConnectAndReceive(filePath, remoteAddr, owner, group string, position int64, encrypted bool, sslClientMode bool, transferType byte, onReady core.TransferReadyFunc) (int64, uint32, int64, error) {
	var slave *RemoteSlave
	if position > 0 {
		slave = b.sm.SelectSlaveForDownload(filePath)
	} else {
		slave = b.sm.SelectSlaveForUpload(filePath)
	}
	if slave == nil {
		return 0, 0, 0, fmt.Errorf("no available slave")
	}

	slave.IncActiveTransfers()
	defer slave.DecActiveTransfers()

	// Parse remote address
	parts := strings.SplitN(remoteAddr, ":", 2)
	if len(parts) != 2 {
		return 0, 0, 0, fmt.Errorf("invalid remote address: %s", remoteAddr)
	}
	remoteIP := parts[0]
	remotePort, _ := strconv.Atoi(parts[1])

	// Tell slave to connect out to the remote address (with TLS for FXP)
	// sslClientHandshake=false: slave acts as TLS SERVER (other site did CPSV, is TLS client)
	connectIdx, err := IssueConnect(slave, remoteIP, remotePort, encrypted, sslClientMode)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("issue connect to %s: %w", slave.Name(), err)
	}

	resp, err := slave.FetchResponse(connectIdx, 60*time.Second)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("slave %s connect failed: %w", slave.Name(), err)
	}

	transferResp, ok := resp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return 0, 0, 0, fmt.Errorf("unexpected response from slave")
	}
	if onReady != nil {
		onReady(slave.Name(), transferResp.Info.TransferIndex)
	}

	// Tell slave to receive the file on this connection
	recvIdx, err := IssueReceive(slave, filePath, transferType, position, remoteAddr,
		transferResp.Info.TransferIndex)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("issue receive: %w", err)
	}

	// Wait for receive ACK
	_, err = slave.FetchResponse(recvIdx, 60*time.Second)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("receive ack: %w", err)
	}
	b.notePendingUpload(filePath, slave.Name(), owner, group, position)
	defer b.clearPendingUpload(filePath)

	status, err := slave.WaitTransferStatus(transferResp.Info.TransferIndex, 2*time.Hour)
	if err != nil {
		b.reconcileFailedUploadState(filePath, slave)
		return 0, 0, 0, err
	}
	if status.Error != "" {
		b.reconcileFailedUploadState(filePath, slave)
		return status.Transferred, status.Checksum, status.Elapsed, fmt.Errorf("%s", status.Error)
	}

	finalSize := finalUploadFileSize(status, position)
	finalChecksum := status.Checksum
	if position > 0 {
		if checksum, err := b.ChecksumFile(filePath); err == nil {
			finalChecksum = checksum
		}
	}

	b.sm.GetVFS().AddFile(filePath, VFSFile{
		Path:         filePath,
		Size:         finalSize,
		IsDir:        false,
		LastModified: time.Now().Unix(),
		SlaveName:    slave.Name(),
		Owner:        owner,
		Group:        group,
		XferTime:     status.Elapsed,
		Checksum:     finalChecksum,
		Seen:         true,
	})
	b.recordUploadMetadata(filePath, owner, group, finalSize, status.Elapsed, finalChecksum)
	b.sm.SyncStatusMarkersForPath(filePath, false)

	log.Printf("[Passthrough-PORT] Upload %s on %s (%d bytes, %dms, CRC=%08X)",
		filePath, slave.Name(), finalSize, status.Elapsed, finalChecksum)

	return finalSize, finalChecksum, status.Elapsed, nil
}

// SlaveConnectAndSend tells the owning slave to connect out to a remote address (PORT mode passthrough)
// and send a file directly. The master only orchestrates the control flow.
func (b *Bridge) SlaveConnectAndSend(filePath, remoteAddr, username, primaryGroup string, position int64, encrypted bool, sslClientMode bool, transferType byte, onReady core.TransferReadyFunc) (uint32, int64, error) {
	slave := b.selectSlaveForDownloadIncludingPending(filePath)
	if slave == nil {
		return 0, 0, fmt.Errorf("file not found on any available slave: %s", filePath)
	}

	slave.IncActiveTransfers()
	defer slave.DecActiveTransfers()

	parts := strings.SplitN(remoteAddr, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid remote address: %s", remoteAddr)
	}
	remoteIP := parts[0]
	remotePort, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid remote address: %s", remoteAddr)
	}

	connectIdx, err := IssueConnect(slave, remoteIP, remotePort, encrypted, sslClientMode)
	if err != nil {
		return 0, 0, fmt.Errorf("issue connect to %s: %w", slave.Name(), err)
	}

	resp, err := slave.FetchResponse(connectIdx, 60*time.Second)
	if err != nil {
		return 0, 0, fmt.Errorf("slave %s connect failed: %w", slave.Name(), err)
	}

	transferResp, ok := resp.(*protocol.AsyncResponseTransfer)
	if !ok {
		return 0, 0, fmt.Errorf("unexpected response from slave")
	}
	if onReady != nil {
		onReady(slave.Name(), transferResp.Info.TransferIndex)
	}

	sendIdx, err := IssueSend(slave, filePath, transferType, position, remoteAddr, transferResp.Info.TransferIndex)
	if err != nil {
		IssueAbort(slave, transferResp.Info.TransferIndex, "download send setup failed")
		return 0, 0, fmt.Errorf("issue send: %w", err)
	}
	if _, err := slave.FetchResponse(sendIdx, 60*time.Second); err != nil {
		IssueAbort(slave, transferResp.Info.TransferIndex, "download send ack failed")
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, 0, fmt.Errorf("send ack: %w", err)
	}

	status, err := slave.WaitTransferStatus(transferResp.Info.TransferIndex, 2*time.Hour)
	if err != nil {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, 0, err
	}
	if status.Error != "" {
		b.reconcileUnavailableDownloadState(filePath, slave)
		return 0, 0, fmt.Errorf("%s", status.Error)
	}
	if position > 0 {
		return 0, status.Elapsed, nil
	}
	b.repairDownloadedFileSize(filePath, status.Transferred)
	return status.Checksum, status.Elapsed, nil
}
