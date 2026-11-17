package master

import (
	"encoding/gob"
	"fmt"
	"log"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"weaveftpd/internal/core"
	"weaveftpd/internal/metrics"
	"weaveftpd/internal/plugin"
	"weaveftpd/internal/zipscript"
)

// VFSFile represents a file or directory in the master's virtual file system.
type VFSFile struct {
	Path         string
	Size         int64
	IsDir        bool
	IsSymlink    bool
	VirtualOnly  bool // Master-owned link; slave scans must not replace it.
	LinkTarget   string
	Mode         uint32
	LastModified int64
	SlaveName    string
	Owner        string
	Group        string
	Seen         bool   // Used to detect and purge deleted ghost files
	XferTime     int64  // transfer time in milliseconds (for speed calc)
	Checksum     uint32 // CRC32 from transfer
}

// VFSDirMeta holds per-directory metadata cached on the VFS (like drftpd's pluginMetaData).
// Stored separately from file entries.
type VFSDirMeta struct {
	SFVEntries          map[string]uint32 // filename -> CRC32 from parsed SFV
	SFVName             string            // name of the .sfv file
	SFVChecksum         uint32            // CRC32 of the .sfv file itself, when known
	SFVAllowWithoutFile bool              // compatibility for direct test metadata injection
	ZipExpectedParts    int
	ZipDIZChecksum      uint32
	RequestEntries      []plugin.RequestRecord
	RequestFillEntries  []plugin.RequestFillRecord

	raceCache    *VFSRaceCache
	zipRaceCache *VFSRaceCache
}

type VFSRaceCache struct {
	Users      []RaceUserStat
	Groups     []RaceGroupStat
	TotalBytes int64
	Present    int
	Total      int
}

type VFSSearchResult struct {
	Path    string
	Files   int
	Bytes   int64
	ModTime int64
}

type vfsSnapshot struct {
	Files   map[string]*VFSFile
	DirMeta map[string]*VFSDirMeta
}

// copyVFSDirMeta returns an independent deep copy of meta, safe to hand to a
// caller outside vfs.mu (used by GetSFVData and SaveToDisk). raceCache/
// zipRaceCache are intentionally omitted: they are internal cache state, never
// part of the public GetSFVData contract, and always nil right after any
// mutator that would make this copy visible (each invalidates the cache).
func copyVFSDirMeta(meta *VFSDirMeta) *VFSDirMeta {
	if meta == nil {
		return nil
	}
	cp := &VFSDirMeta{
		SFVName:             meta.SFVName,
		SFVChecksum:         meta.SFVChecksum,
		SFVAllowWithoutFile: meta.SFVAllowWithoutFile,
		ZipExpectedParts:    meta.ZipExpectedParts,
		ZipDIZChecksum:      meta.ZipDIZChecksum,
	}
	if len(meta.SFVEntries) > 0 {
		cp.SFVEntries = make(map[string]uint32, len(meta.SFVEntries))
		for name, crc := range meta.SFVEntries {
			cp.SFVEntries[name] = crc
		}
	}
	if len(meta.RequestEntries) > 0 {
		cp.RequestEntries = append([]plugin.RequestRecord(nil), meta.RequestEntries...)
	}
	if len(meta.RequestFillEntries) > 0 {
		cp.RequestFillEntries = append([]plugin.RequestFillRecord(nil), meta.RequestFillEntries...)
	}
	return cp
}

// VirtualFileSystem maintains the master's view of files across all slaves.
//
//	/ VirtualFileSystemDirectory.
//
// Invariant: once a *VFSFile is stored in files, its fields must never be
// mutated again - every update builds a new VFSFile and replaces the map
// entry (see AddFile). GetFile/ListDirectory/GetAllFiles rely on this to hand
// out live pointers without copying: a published pointer is a frozen
// snapshot, never touched again, only superseded by a new pointer under the
// same key. Breaking this invariant reintroduces a data race between readers
// holding an old pointer and writers mutating it in place.
type VirtualFileSystem struct {
	files          map[string]*VFSFile
	children       map[string]map[string]struct{}
	slavePaths     map[string]map[string]struct{}
	dirMeta        map[string]*VFSDirMeta // dir path -> metadata (SFV cache etc)
	protectedDirs  map[string]bool
	hiddenPaths    map[string]bool
	excludePaths   map[string]bool
	persistVersion uint64
	savedVersion   uint64
	mu             sync.RWMutex
}

// SlaveNames returns the distinct non-empty slave names currently present in the VFS.
func (vfs *VirtualFileSystem) SlaveNames() []string {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, file := range vfs.files {
		if file == nil || file.SlaveName == "" {
			continue
		}
		seen[file.SlaveName] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func NewVirtualFileSystem() *VirtualFileSystem {
	vfs := &VirtualFileSystem{
		files:         make(map[string]*VFSFile),
		children:      make(map[string]map[string]struct{}),
		slavePaths:    make(map[string]map[string]struct{}),
		dirMeta:       make(map[string]*VFSDirMeta),
		protectedDirs: make(map[string]bool),
		hiddenPaths:   make(map[string]bool),
		excludePaths:  make(map[string]bool),
	}
	vfs.files["/"] = &VFSFile{Path: "/", IsDir: true, Seen: true}
	vfs.children["/"] = make(map[string]struct{})
	return vfs
}

func (vfs *VirtualFileSystem) AddFile(path string, file VFSFile) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	// Normalize path
	path = cleanVFSPath(path)
	file.Path = path
	if file.LinkTarget != "" {
		file.LinkTarget = cleanVFSPath(file.LinkTarget)
	}
	if vfs.protectedDirs == nil {
		vfs.protectedDirs = make(map[string]bool)
	}
	if vfs.hiddenPaths == nil {
		vfs.hiddenPaths = make(map[string]bool)
	}
	if vfs.excludePaths == nil {
		vfs.excludePaths = make(map[string]bool)
	}
	if vfs.isExcludedPathLocked(path) {
		vfs.deleteFileEntryOnlyLocked(path)
		vfs.invalidateRaceCachesForPathLocked(path)
		return
	}
	if vfs.isHiddenPathLocked(path) {
		vfs.deleteFileEntryOnlyLocked(path)
		vfs.invalidateRaceCachesForPathLocked(path)
		return
	}
	for ancestor := path; ancestor != "/" && ancestor != "."; ancestor = cleanVFSPath(filepath.Dir(ancestor)) {
		if entry := vfs.files[ancestor]; entry != nil && entry.IsSymlink && entry.VirtualOnly {
			return
		}
	}
	if vfs.protectedDirs[path] {
		file.IsDir = true
		file.IsSymlink = false
		file.LinkTarget = ""
		file.Seen = true
		file.SlaveName = ""
	}
	if file.IsSymlink && file.LinkTarget != "" {
		if existing := vfs.files[path]; existing != nil && existing.IsDir {
			file.IsDir = true
		}
		if target := vfs.files[file.LinkTarget]; target != nil && target.IsDir {
			file.IsDir = true
		}
	}
	if existing := vfs.files[path]; existing != nil {
		if isWeakMetadataValue(file.Owner) && !isWeakMetadataValue(existing.Owner) {
			file.Owner = existing.Owner
		}
		if isWeakMetadataValue(file.Group) && !isWeakMetadataValue(existing.Group) {
			file.Group = existing.Group
		}
		// Don't let an evidence-free re-scan SHRINK a size that a completed upload
		// already recorded. A real upload sets XferTime+Checksum (the slave CRCs
		// every received file, incl. the .sfv); a remerge/scan carries neither and
		// reads the live on-disk size, which is short/0 if it catches a file still
		// being written. Without this, a remerge clobbers a correct size to 0 and
		// the listing shows the file (e.g. the .sfv) as empty, so cbftp skips it.
		// Previously this guard was scoped to .zip payloads only.
		if !file.IsDir && !file.IsSymlink &&
			!existing.IsDir && !existing.IsSymlink &&
			file.XferTime == 0 && file.Checksum == 0 &&
			existing.XferTime > 0 && existing.Checksum != 0 &&
			existing.Size > file.Size {
			file.Size = existing.Size
		}
		if !file.IsDir && !file.IsSymlink &&
			!existing.IsDir && !existing.IsSymlink &&
			existing.Size == file.Size {
			if file.Checksum == 0 {
				file.Checksum = existing.Checksum
			}
			if file.XferTime == 0 {
				file.XferTime = existing.XferTime
			}
		}
	}

	oldSlave := ""
	if existing := vfs.files[path]; existing != nil {
		oldSlave = existing.SlaveName
	}
	vfs.files[path] = &file
	vfs.reindexSlavePathLocked(path, oldSlave, file.SlaveName)
	vfs.ensureParentDirsLocked(path, file.SlaveName)
	vfs.linkChildLocked(cleanVFSPath(pathpkg.Dir(path)), path)
	if file.IsDir {
		vfs.ensureChildrenBucketLocked(path)
	}
	vfs.invalidateRaceCachesForPathLocked(path)
	vfs.touchAncestorsLocked(path, file.LastModified)
	vfs.markPersistDirtyLocked()
}

// UpdateFileVerification refreshes checksum-backed verification data for an
// existing file without replacing the whole entry.
func (vfs *VirtualFileSystem) UpdateFileVerification(path string, checksum uint32) bool {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	path = cleanVFSPath(path)
	file := vfs.files[path]
	if file == nil || file.IsDir {
		return false
	}
	cp := *file
	cp.Checksum = checksum
	vfs.files[path] = &cp
	vfs.invalidateRaceCachesForPathLocked(path)
	vfs.markPersistDirtyLocked()
	return true
}

func (vfs *VirtualFileSystem) UpdateFileTransferSize(path string, sizeBytes int64) bool {
	if sizeBytes <= 0 {
		return false
	}
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	path = cleanVFSPath(path)
	file := vfs.files[path]
	if file == nil || file.IsDir {
		return false
	}
	// Never let an in-flight transfer's running size touch an entry that already
	// has a verified completion (real upload sets XferTime+Checksum). Otherwise a
	// leech download that follows a file and stops at a partial offset can grow a
	// fresh/weak entry to that partial and leave it stuck there (e.g. a .zip listing
	// 444k instead of its real size), which cbftp then races short.
	if file.XferTime > 0 && file.Checksum != 0 {
		return false
	}
	if sizeBytes <= file.Size {
		return false
	}
	cp := *file
	cp.Size = sizeBytes
	vfs.files[path] = &cp
	vfs.invalidateRaceCachesForPathLocked(path)
	vfs.markPersistDirtyLocked()
	return true
}

// ScrubReleaseRaceMetadata neutralizes a release tree after it moves out of a
// private race area. Ownership is rewritten for listings, while transfer times
// are cleared so CWD/STOR race stats no longer expose the original racers.
func (vfs *VirtualFileSystem) ScrubReleaseRaceMetadata(rootPath, owner, group string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	rootPath = cleanVFSPath(rootPath)
	owner = strings.TrimSpace(owner)
	group = strings.TrimSpace(group)
	changed := false
	affectedDirs := make(map[string]struct{})
	for filePath, file := range vfs.files {
		if file == nil {
			continue
		}
		if filePath != rootPath && !strings.HasPrefix(filePath, rootPath+"/") {
			continue
		}
		fileChanged := false
		cp := *file
		if owner != "" && cp.Owner != owner {
			cp.Owner = owner
			fileChanged = true
		}
		if group != "" && cp.Group != group {
			cp.Group = group
			fileChanged = true
		}
		if !cp.IsDir && cp.XferTime != 0 {
			cp.XferTime = 0
			fileChanged = true
		}
		if fileChanged {
			vfs.files[filePath] = &cp
			changed = true
			affectedDirs[cleanVFSPath(pathpkg.Dir(filePath))] = struct{}{}
		}
	}
	if changed {
		// Only the scrubbed subtree's race stats changed; invalidate just those
		// directories instead of wiping every dir's cache (which would force a
		// full recompute on the next listing of every release on the site).
		for dir := range affectedDirs {
			vfs.invalidateRaceCacheLocked(dir)
		}
		vfs.markPersistDirtyLocked()
	}
}

func (vfs *VirtualFileSystem) SetHiddenPaths(paths []string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	vfs.hiddenPaths = make(map[string]bool, len(paths))
	for _, p := range paths {
		p = cleanVFSPath(p)
		if p == "" || p == "." || p == "/" {
			continue
		}
		vfs.hiddenPaths[p] = true
	}
	vfs.pruneHiddenPathsLocked()
}

func (vfs *VirtualFileSystem) SetExcludePaths(paths []string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	vfs.excludePaths = make(map[string]bool, len(paths))
	for _, p := range paths {
		p = cleanVFSPath(p)
		if p == "" || p == "." || p == "/" {
			continue
		}
		vfs.excludePaths[p] = true
	}
	vfs.pruneExcludedPathsLocked()
}

func (vfs *VirtualFileSystem) AddSymlink(linkPath, targetPath string) {
	vfs.addSymlink(linkPath, targetPath, false)
}

func (vfs *VirtualFileSystem) AddVirtualSymlink(linkPath, targetPath string) {
	vfs.addSymlink(linkPath, targetPath, true)
}

func (vfs *VirtualFileSystem) addSymlink(linkPath, targetPath string, virtualOnly bool) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	linkPath = cleanVFSPath(linkPath)
	targetPath = cleanVFSPath(targetPath)
	if existing := vfs.files[linkPath]; virtualOnly && existing != nil && (!existing.IsSymlink || !existing.VirtualOnly) {
		// Drop shadow entries from the index only, never files on slave storage.
		vfs.deletePathLocked(linkPath)
	}
	isDir := true
	if target := vfs.files[targetPath]; target != nil {
		isDir = target.IsDir
	}
	if existing := vfs.files[linkPath]; existing != nil && existing.IsSymlink && existing.LinkTarget == targetPath && existing.VirtualOnly == virtualOnly {
		cp := *existing
		cp.IsDir = isDir
		cp.Seen = true
		vfs.files[linkPath] = &cp
		return
	}
	vfs.files[linkPath] = &VFSFile{
		Path:         linkPath,
		IsDir:        isDir,
		IsSymlink:    true,
		VirtualOnly:  virtualOnly,
		LinkTarget:   targetPath,
		Mode:         0777,
		LastModified: time.Now().Unix(),
		Seen:         true,
	}
	vfs.ensureParentDirsLocked(linkPath, "")
	vfs.linkChildLocked(cleanVFSPath(pathpkg.Dir(linkPath)), linkPath)
	if isDir {
		vfs.ensureChildrenBucketLocked(linkPath)
	}
	vfs.invalidateRaceCachesForPathLocked(linkPath)
	vfs.touchAncestorsLocked(linkPath, time.Now().Unix())
	vfs.markPersistDirtyLocked()
}

func (vfs *VirtualFileSystem) Chmod(path string, mode uint32) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	path = cleanVFSPath(path)
	if f := vfs.files[path]; f != nil {
		cp := *f
		cp.Mode = mode
		cp.LastModified = time.Now().Unix()
		vfs.files[path] = &cp
		vfs.markPersistDirtyLocked()
	}
}

// MarkAllUnseen flags all files for a specific slave as unseen before a remerge.
func (vfs *VirtualFileSystem) MarkAllUnseen(slaveName string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()
	for _, path := range vfs.pathsForSlaveLocked(slaveName) {
		file := vfs.files[path]
		if file == nil {
			vfs.removeSlavePathLocked(slaveName, path)
			continue
		}
		if vfs.protectedDirs[path] {
			vfs.reindexSlavePathLocked(path, file.SlaveName, "")
			cp := *file
			cp.Seen = true
			cp.SlaveName = ""
			vfs.files[path] = &cp
			continue
		}
		if file.SlaveName == slaveName {
			cp := *file
			cp.Seen = false
			vfs.files[path] = &cp
		}
	}
}

// MarkSubtreeUnseen flags files for a specific slave as unseen below rootPath
// before a scoped remerge. This lets scoped remerges purge ghost entries
// without touching unrelated sections.
func (vfs *VirtualFileSystem) MarkSubtreeUnseen(slaveName, rootPath string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	rootPath = cleanVFSPath(rootPath)
	vfs.resetProtectedDirsLocked()
	for _, path := range vfs.collectSubtreePathsLocked(rootPath) {
		if vfs.protectedDirs[path] {
			continue
		}
		if file := vfs.files[path]; file != nil && file.SlaveName == slaveName {
			cp := *file
			cp.Seen = false
			vfs.files[path] = &cp
		}
	}
}

// collectSubtreePathsLocked returns rootPath plus every descendant path by
// walking the children index, so scoped remerge ops cost O(subtree) instead of
// scanning the whole file map under the write lock. Paths are gathered into a
// slice up front so callers may safely delete during iteration.
func (vfs *VirtualFileSystem) collectSubtreePathsLocked(rootPath string) []string {
	out := []string{rootPath}
	stack := []string{rootPath}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for childPath := range vfs.children[dir] {
			out = append(out, childPath)
			if _, isDir := vfs.children[childPath]; isDir {
				stack = append(stack, childPath)
			}
		}
	}
	return out
}

// resetProtectedDirsLocked keeps protected dirs marked seen and slave-agnostic so
// a remerge never flags or purges them. Iterates the (small) protected set rather
// than every file.
func (vfs *VirtualFileSystem) resetProtectedDirsLocked() {
	for path, protected := range vfs.protectedDirs {
		if !protected {
			continue
		}
		if file := vfs.files[path]; file != nil {
			vfs.reindexSlavePathLocked(path, file.SlaveName, "")
			cp := *file
			cp.Seen = true
			cp.SlaveName = ""
			vfs.files[path] = &cp
		}
	}
}

// PurgeUnseen removes any files for a specific slave that were not seen during the remerge.
func (vfs *VirtualFileSystem) PurgeUnseen(slaveName string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()
	nowUnix := time.Now().Unix()
	changed := false
	for _, path := range vfs.pathsForSlaveLocked(slaveName) {
		file := vfs.files[path]
		if file == nil {
			vfs.removeSlavePathLocked(slaveName, path)
			continue
		}
		if vfs.protectedDirs[path] {
			vfs.reindexSlavePathLocked(path, file.SlaveName, "")
			cp := *file
			cp.Seen = true
			cp.SlaveName = ""
			vfs.files[path] = &cp
			continue
		}
		if file.SlaveName == slaveName && !file.Seen {
			// Don't purge a file that was just uploaded: an FXP upload can land
			// after the slave snapshot but before this purge, so it is still
			// marked unseen yet legitimately present (incl. the .sfv). If it is
			// genuinely gone, the next remerge past the grace window reconciles it.
			if file.LastModified > 0 && nowUnix-file.LastModified < remergePurgeRecencyGraceSec {
				continue
			}
			changed = vfs.deletePathLocked(path) || changed
		}
	}
	if changed {
		vfs.markPersistDirtyLocked()
	}
}

// PurgeUnseenSubtree removes stale files below rootPath after a scoped remerge.
func (vfs *VirtualFileSystem) PurgeUnseenSubtree(slaveName, rootPath string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	rootPath = cleanVFSPath(rootPath)
	vfs.resetProtectedDirsLocked()
	nowUnix := time.Now().Unix()
	changed := false
	for _, path := range vfs.collectSubtreePathsLocked(rootPath) {
		if vfs.protectedDirs[path] {
			continue
		}
		file := vfs.files[path]
		if file != nil && file.SlaveName == slaveName && !file.Seen {
			// Spare a just-uploaded file that landed after the slave snapshot but
			// before this purge (still unseen, but present); reconciled next pass.
			if file.LastModified > 0 && nowUnix-file.LastModified < remergePurgeRecencyGraceSec {
				continue
			}
			changed = vfs.deletePathLocked(path) || changed
		}
	}
	if changed {
		vfs.markPersistDirtyLocked()
	}
}

// remergePurgeRecencyGraceSec protects files modified within this many seconds
// from snapshot-based pruning, covering uploads that land during a remerge.
const remergePurgeRecencyGraceSec int64 = 120

// PurgeMissingChildren removes stale direct children for a remerged directory
// immediately, using the directory snapshot reported by the slave.
func (vfs *VirtualFileSystem) PurgeMissingChildren(slaveName, dirPath string, present map[string]struct{}, protectedSubtrees []string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	dirPath = cleanVFSPath(dirPath)
	childPaths := vfs.children[dirPath]
	if len(childPaths) == 0 {
		return
	}

	nowUnix := time.Now().Unix()
	changed := false
	for childPath := range childPaths {
		file := vfs.files[childPath]
		if file == nil {
			continue
		}
		if file.SlaveName != slaveName {
			continue
		}
		if _, ok := present[childPath]; ok {
			continue
		}
		if isProtectedRemergeChild(childPath, protectedSubtrees) {
			continue
		}
		// Don't purge a child that was just created/modified: a concurrent upload
		// may have added it after the slave snapshotted this directory, so it is
		// missing from the snapshot but legitimately present. If it is genuinely
		// gone, the next remerge (past the grace window) will reconcile it.
		if file.LastModified > 0 && nowUnix-file.LastModified < remergePurgeRecencyGraceSec {
			continue
		}
		changed = vfs.deletePathLocked(childPath) || changed
	}
	if changed {
		vfs.markPersistDirtyLocked()
	}
}

func isProtectedRemergeChild(childPath string, protectedSubtrees []string) bool {
	childPath = cleanVFSPath(childPath)
	for _, protected := range protectedSubtrees {
		protected = cleanVFSPath(protected)
		if protected == "" || protected == "." {
			continue
		}
		if childPath == protected || strings.HasPrefix(childPath, protected+"/") {
			return true
		}
	}
	return false
}

func (vfs *VirtualFileSystem) SetProtectedDirs(paths []string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	vfs.protectedDirs = make(map[string]bool, len(paths)+1)
	vfs.protectedDirs["/"] = true
	for _, p := range paths {
		p = cleanVFSPath(p)
		if p == "" || p == "." {
			continue
		}
		vfs.protectedDirs[p] = true
		f := vfs.files[p]
		if f != nil {
			vfs.reindexSlavePathLocked(p, f.SlaveName, "")
			cp := *f
			cp.Path = p
			cp.IsDir = true
			cp.Seen = true
			cp.SlaveName = ""
			vfs.files[p] = &cp
		}
	}
	for p, f := range vfs.files {
		p = cleanVFSPath(p)
		if p == "/" || vfs.protectedDirs[p] {
			continue
		}
		if f == nil || !f.IsDir {
			continue
		}
		if cleanVFSPath(pathpkg.Dir(p)) != "/" {
			continue
		}
		if strings.TrimSpace(f.SlaveName) != "" {
			continue
		}
		vfs.deleteFileEntryOnlyLocked(p)
	}
	vfs.rebuildChildrenLocked()
	vfs.markPersistDirtyLocked()
}

func (vfs *VirtualFileSystem) GetFile(path string) *VFSFile {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	path = cleanVFSPath(path)
	if vfs.isExcludedPathLocked(path) {
		return nil
	}
	if vfs.isHiddenPathLocked(path) {
		return nil
	}
	return vfs.files[path]
}

func (vfs *VirtualFileSystem) ResolvePath(p string) string {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	current := cleanVFSPath(p)
	if current == "/" {
		return current
	}

	parts := strings.Split(strings.TrimPrefix(current, "/"), "/")
	current = "/"
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		next := cleanVFSPath(pathpkg.Join(current, part))
		if f := vfs.files[next]; f != nil && f.IsSymlink && strings.TrimSpace(f.LinkTarget) != "" {
			current = cleanVFSPath(f.LinkTarget)
			continue
		}
		current = next
	}
	return current
}

func (vfs *VirtualFileSystem) DeleteFile(path string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	path = cleanVFSPath(path)
	if path == "/" {
		return
	}
	if !vfs.deletePathLocked(path) {
		return
	}
	parent := cleanVFSPath(pathpkg.Dir(path))
	vfs.touchAncestorsLocked(parent, time.Now().Unix())
	vfs.markPersistDirtyLocked()
}

func (vfs *VirtualFileSystem) deletePathLocked(path string) bool {
	path = cleanVFSPath(path)
	parent := cleanVFSPath(pathpkg.Dir(path))
	baseLower := strings.ToLower(pathpkg.Base(path))
	if vfs.files[path] == nil {
		return false
	}
	if strings.HasSuffix(strings.ToLower(pathpkg.Base(path)), ".sfv") {
		if meta := vfs.dirMeta[parent]; meta != nil {
			meta.SFVName = ""
			meta.SFVEntries = nil
			meta.SFVChecksum = 0
			meta.SFVAllowWithoutFile = false
			delete(vfs.dirMeta, parent)
		}
	}
	clearZipMeta := baseLower == "file_id.diz" || strings.HasSuffix(baseLower, ".zip")
	removed := vfs.collectSubtreePathsLocked(path)
	if len(removed) == 0 {
		return false
	}
	vfs.invalidateRaceCachesForPathLocked(path)
	if children := vfs.children[parent]; children != nil {
		delete(children, path)
	}
	for _, removedPath := range removed {
		vfs.deleteFileEntryOnlyLocked(removedPath)
		vfs.invalidateRaceCachesForPathLocked(removedPath)
		delete(vfs.children, removedPath)
		delete(vfs.dirMeta, removedPath)
		if removedPath == path {
			continue
		}
		if children := vfs.children[cleanVFSPath(pathpkg.Dir(removedPath))]; children != nil {
			delete(children, removedPath)
		}
	}
	if clearZipMeta && !vfs.hasZipArchiveLocked(parent) {
		vfs.clearZipMetaLocked(parent)
	} else if baseLower == "file_id.diz" {
		vfs.clearZipMetaLocked(parent)
	}
	return true
}

// ListDirectory returns direct children of a directory.
func (vfs *VirtualFileSystem) ListDirectory(dirPath string) []*VFSFile {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	dirPath = cleanVFSPath(dirPath)
	childPaths := vfs.children[dirPath]
	if len(childPaths) == 0 {
		return nil
	}

	results := make([]*VFSFile, 0, len(childPaths))
	for childPath := range childPaths {
		if vfs.isHiddenPathLocked(childPath) {
			continue
		}
		if !isDirectVFSChildPath(dirPath, childPath) {
			continue
		}
		if file := vfs.files[childPath]; file != nil {
			results = append(results, file)
		}
	}

	return results
}

func isDirectVFSChildPath(parent, child string) bool {
	if parent == "/" {
		rest := strings.TrimPrefix(child, "/")
		return rest != "" && !strings.Contains(rest, "/")
	}
	prefix := parent + "/"
	if !strings.HasPrefix(child, prefix) {
		return false
	}
	rest := strings.TrimPrefix(child, prefix)
	return rest != "" && !strings.Contains(rest, "/")
}

// checksumKnownMismatch reports whether expected and actual are both known
// (non-zero) checksums that disagree. A zero on either side means the
// checksum hasn't been computed/verified yet and must never be treated as a
// mismatch: a same-day revert (9f14bae, reverted by a6d8f4c) briefly dropped
// the != 0 guards here and made every not-yet-verified present file register
// as permanently missing.
func checksumKnownMismatch(expected, actual uint32) bool {
	return expected != 0 && actual != 0 && expected != actual
}

// isChecksumVerified reports whether actual is a confirmed match for
// expected, or expected itself is unknown (nothing to verify against, so
// presence alone counts). Note an unknown actual checksum against a known
// expected is NOT verified, even though that pairing isn't a
// checksumKnownMismatch either -- the two functions answer different
// questions (proven-different vs. proven-same-or-unverifiable) and callers
// need to pick the one matching what they're deciding.
func isChecksumVerified(expected, actual uint32) bool {
	return expected == 0 || (actual != 0 && actual == expected)
}

func (vfs *VirtualFileSystem) GetReleaseStatus(dirPath string) (core.ReleaseStatus, bool) {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	dirPath = cleanVFSPath(dirPath)
	if vfs.isHiddenPathLocked(dirPath) {
		return core.ReleaseStatus{}, false
	}
	entry := vfs.files[dirPath]
	if entry == nil || !entry.IsDir || entry.IsSymlink {
		return core.ReleaseStatus{}, false
	}

	status := core.ReleaseStatus{Path: dirPath}
	for childPath := range vfs.children[dirPath] {
		if vfs.isHiddenPathLocked(childPath) {
			continue
		}
		child := vfs.files[childPath]
		if child == nil {
			continue
		}
		name := strings.TrimSpace(pathpkg.Base(child.Path))
		if strings.HasPrefix(name, ".") {
			continue
		}
		status.VisibleCount++
		if child.IsDir {
			continue
		}
		status.FileCount++
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".sfv") {
			status.HasSFV = true
		}
		if strings.HasSuffix(lower, ".nfo") {
			status.HasNFO = true
		}
	}

	if meta := vfs.dirMeta[dirPath]; vfs.sfvMetaValidLocked(dirPath, meta) {
		status.Kind = "sfv"
		expectedFiles := make([]string, 0, len(meta.SFVEntries))
		missingFiles := make([]string, 0, len(meta.SFVEntries))
		presentFiles := make(map[string]*VFSFile, len(vfs.children[dirPath]))
		for childPath := range vfs.children[dirPath] {
			f := vfs.files[childPath]
			if f == nil || f.IsDir {
				continue
			}
			presentFiles[raceFileKey(pathpkg.Base(childPath))] = f
		}
		for sfvFile, expectedCRC := range meta.SFVEntries {
			key := raceFileKey(sfvFile)
			expectedFiles = append(expectedFiles, sfvFile)
			f := presentFiles[key]
			if f == nil {
				missingFiles = append(missingFiles, sfvFile)
				continue
			}
			if checksumKnownMismatch(expectedCRC, f.Checksum) {
				missingFiles = append(missingFiles, sfvFile)
				continue
			}
			status.Present++
			status.TotalBytes += f.Size
		}
		sort.Strings(expectedFiles)
		sort.Strings(missingFiles)
		status.ExpectedFiles = expectedFiles
		status.MissingFiles = missingFiles
		status.Total = len(expectedFiles)
		return status, true
	}

	if expected, ok := vfs.getZipExpectedPartsLocked(dirPath); ok {
		status.Kind = "zip"
		status.Total = expected
		for childPath := range vfs.children[dirPath] {
			if vfs.isHiddenPathLocked(childPath) {
				continue
			}
			child := vfs.files[childPath]
			if child == nil || child.IsDir || child.IsSymlink {
				continue
			}
			name := strings.TrimSpace(pathpkg.Base(child.Path))
			if strings.HasPrefix(name, ".") || !zipscript.IsZipPayloadName(name) {
				continue
			}
			status.Present++
			status.TotalBytes += child.Size
		}
		return status, true
	}

	return status, true
}

// GetVerifiedSFVPresentFiles returns the SFV-tracked filenames that are
// currently present and checksum-valid in dirPath, keyed by normalized base
// filename.
func (vfs *VirtualFileSystem) GetVerifiedSFVPresentFiles(dirPath string) map[string]bool {
	return vfs.GetVerifiedSFVPresentFilesFiltered(dirPath, nil)
}

// GetVerifiedSFVPresentFilesFiltered is like GetVerifiedSFVPresentFiles but
// excludes normalized basenames present in excludeKeys. This is used to avoid
// counting files that still exist in the VFS but are actively uploading.
func (vfs *VirtualFileSystem) GetVerifiedSFVPresentFilesFiltered(dirPath string, excludeKeys map[string]bool) map[string]bool {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	return vfs.getVerifiedSFVPresentFilesLocked(dirPath, excludeKeys)
}

func (vfs *VirtualFileSystem) getVerifiedSFVPresentFilesLocked(dirPath string, excludeKeys map[string]bool) map[string]bool {
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if !vfs.sfvMetaValidLocked(dirPath, meta) {
		return nil
	}

	presentFiles := make(map[string]*VFSFile)
	for childPath := range vfs.children[dirPath] {
		f := vfs.files[childPath]
		if f == nil || f.IsDir {
			continue
		}
		presentFiles[raceFileKey(pathpkg.Base(childPath))] = f
	}

	verified := make(map[string]bool, len(meta.SFVEntries))
	for sfvFile, expectedCRC := range meta.SFVEntries {
		key := raceFileKey(sfvFile)
		f := presentFiles[key]
		if f == nil {
			continue
		}
		if !isChecksumVerified(expectedCRC, f.Checksum) {
			continue
		}
		// A confirmed match counts even if a lagging live-stat still lists
		// this file as uploading; only the expected-unknown case defers to
		// excludeKeys, since there's nothing else to verify against there.
		if expectedCRC == 0 && excludeKeys[key] {
			continue
		}
		verified[key] = true
	}

	if len(verified) == 0 {
		return nil
	}
	return verified
}

func (vfs *VirtualFileSystem) HydrateRaceFile(path, owner, group string, sizeBytes int64, xferTime int64, checksum uint32) bool {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	path = cleanVFSPath(path)
	file := vfs.files[path]
	if file == nil || file.IsDir {
		return false
	}
	cp := *file
	changed := false
	currentOwner := strings.TrimSpace(cp.Owner)
	currentGroup := strings.TrimSpace(cp.Group)
	if isWeakMetadataValue(currentOwner) && !isWeakMetadataValue(owner) {
		cp.Owner = owner
		changed = true
	}
	if isWeakMetadataValue(currentGroup) && !isWeakMetadataValue(group) {
		cp.Group = group
		changed = true
	}
	if sizeBytes > 0 && sizeBytes > cp.Size && (cp.Size <= 0 || (cp.XferTime <= 0 && cp.Checksum == 0)) {
		cp.Size = sizeBytes
		changed = true
	}
	if cp.XferTime <= 0 && xferTime > 0 {
		cp.XferTime = xferTime
		changed = true
	}
	if cp.Checksum == 0 && checksum != 0 {
		cp.Checksum = checksum
		changed = true
	}
	if changed {
		vfs.files[path] = &cp
		vfs.markPersistDirtyLocked()
	}
	return changed
}

func isWeakMetadataValue(value string) bool {
	value = strings.TrimSpace(value)
	switch {
	case value == "", value == "0":
		return true
	case len(value) == 3 && strings.EqualFold(value, "ftp"):
		return true
	case len(value) == 4 && strings.EqualFold(value, "root"):
		return true
	case strings.EqualFold(value, "weaveftpd"):
		return true
	default:
		return false
	}
}

// FileExists checks if a path exists in the VFS
func (vfs *VirtualFileSystem) FileExists(path string) bool {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	_, exists := vfs.files[cleanVFSPath(path)]
	return exists
}

// GetSlavesForPath returns the names of all slaves that have this file
func (vfs *VirtualFileSystem) GetSlavesForPath(path string) []string {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	file := vfs.files[cleanVFSPath(path)]
	if file == nil {
		return nil
	}
	return []string{file.SlaveName}
}

// RenameFile renames a file/dir in the VFS
func (vfs *VirtualFileSystem) RenameFile(from, to string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	from = cleanVFSPath(from)
	to = cleanVFSPath(to)
	fromParent := cleanVFSPath(pathpkg.Dir(from))
	toParent := cleanVFSPath(pathpkg.Dir(to))
	fromBase := strings.ToLower(strings.TrimSpace(pathpkg.Base(from)))
	toBase := strings.ToLower(strings.TrimSpace(pathpkg.Base(to)))

	file := vfs.files[from]
	if file == nil {
		return
	}

	vfs.moveSubtreeLocked(from, to, "")
	if strings.HasSuffix(fromBase, ".sfv") && (fromParent != toParent || !strings.HasSuffix(toBase, ".sfv")) {
		if meta := vfs.dirMeta[fromParent]; meta != nil {
			meta.SFVName = ""
			meta.SFVEntries = nil
			delete(vfs.dirMeta, fromParent)
		}
	}
	if fromBase == "file_id.diz" && (fromParent != toParent || toBase != "file_id.diz") {
		vfs.clearZipMetaLocked(fromParent)
	}
	if strings.HasSuffix(fromBase, ".zip") && (fromParent != toParent || !strings.HasSuffix(toBase, ".zip")) && !vfs.hasZipArchiveLocked(fromParent) {
		vfs.clearZipMetaLocked(fromParent)
	}
	now := time.Now().Unix()
	vfs.touchAncestorsLocked(fromParent, now)
	vfs.touchAncestorsLocked(toParent, now)
	vfs.markPersistDirtyLocked()
}

func (vfs *VirtualFileSystem) RelocateFile(from, to, newSlaveName string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	from = cleanVFSPath(from)
	to = cleanVFSPath(to)
	fromParent := cleanVFSPath(pathpkg.Dir(from))
	toParent := cleanVFSPath(pathpkg.Dir(to))

	file := vfs.files[from]
	if file == nil {
		return
	}

	vfs.moveSubtreeLocked(from, to, newSlaveName)

	now := time.Now().Unix()
	vfs.touchAncestorsLocked(fromParent, now)
	vfs.touchAncestorsLocked(toParent, now)
	vfs.markPersistDirtyLocked()
}

// ClearSlave removes all files belonging to a slave (called when slave goes offline)
func (vfs *VirtualFileSystem) ClearSlave(slaveName string) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	changed := false
	deletedDirs := make([]string, 0)
	for _, path := range vfs.pathsForSlaveLocked(slaveName) {
		file := vfs.files[path]
		if file == nil || file.SlaveName != slaveName {
			vfs.removeSlavePathLocked(slaveName, path)
			continue
		}
		if file.IsDir {
			deletedDirs = append(deletedDirs, path)
		}
		vfs.deleteFileEntryOnlyLocked(path)
		delete(vfs.dirMeta, path)
		if children := vfs.children[cleanVFSPath(pathpkg.Dir(path))]; children != nil {
			delete(children, path)
		}
		vfs.invalidateRaceCachesForPathLocked(path)
		changed = true
	}
	if changed {
		for _, dirPath := range deletedDirs {
			childPaths := vfs.children[dirPath]
			if len(childPaths) == 0 {
				delete(vfs.children, dirPath)
				continue
			}
			for childPath := range childPaths {
				child := vfs.files[childPath]
				if child == nil {
					delete(childPaths, childPath)
					continue
				}
				vfs.ensureParentDirsLocked(childPath, child.SlaveName)
			}
			if len(childPaths) == 0 && vfs.files[dirPath] == nil {
				delete(vfs.children, dirPath)
			}
		}
		vfs.markPersistDirtyLocked()
	}
}

// GetAllFiles returns all files in the VFS (for debugging)
func (vfs *VirtualFileSystem) GetAllFiles() map[string]*VFSFile {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	result := make(map[string]*VFSFile, len(vfs.files))
	for k, v := range vfs.files {
		result[k] = v
	}
	return result
}

func (vfs *VirtualFileSystem) SearchDirs(query string, limit int) []VFSSearchResult {
	tokens := searchTokens(query)
	if len(tokens) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}

	vfs.mu.RLock()
	defer vfs.mu.RUnlock()

	dirs := make([]*VFSFile, 0)
	for _, f := range vfs.files {
		if f == nil || !f.IsDir || f.Path == "/" {
			continue
		}
		cleanPath := cleanVFSPath(f.Path)
		base := pathpkg.Base(cleanPath)
		pathLower := strings.ToLower(cleanPath)
		baseLower := strings.ToLower(base)
		matched := true
		for _, token := range tokens {
			if !strings.Contains(pathLower, token) && !strings.Contains(baseLower, token) {
				matched = false
				break
			}
		}
		if matched {
			dirs = append(dirs, f)
		}
	}

	sort.Slice(dirs, func(i, j int) bool {
		return strings.ToLower(cleanVFSPath(dirs[i].Path)) < strings.ToLower(cleanVFSPath(dirs[j].Path))
	})

	now := time.Now().Unix()
	results := make([]VFSSearchResult, 0, minInt(limit, len(dirs)))
	for _, dir := range dirs {
		if len(results) >= limit {
			break
		}
		dirPath := cleanVFSPath(dir.Path)
		res := VFSSearchResult{
			Path:    dirPath,
			ModTime: dir.LastModified,
		}
		// Walk only this directory's subtree via the children index instead of
		// rescanning every file in the VFS for each matched directory.
		cf, cb, cm := vfs.subtreeFileStatsLocked(cleanVFSPath(dir.Path))
		res.Files += cf
		res.Bytes += cb
		if cm > res.ModTime {
			res.ModTime = cm
		}
		if res.ModTime <= 0 {
			res.ModTime = now
		}
		results = append(results, res)
	}
	return results
}

// subtreeFileStatsLocked sums file count, bytes and newest mtime under dirPath
// by recursively walking the children index (O(subtree)), avoiding a full
// vfs.files scan per directory. Directory symlinks are not followed, so the
// walk cannot loop. Caller must hold vfs.mu.
func (vfs *VirtualFileSystem) subtreeFileStatsLocked(dirPath string) (files int, bytes int64, modTime int64) {
	for childPath := range vfs.children[dirPath] {
		f := vfs.files[childPath]
		if f == nil {
			continue
		}
		if f.IsDir {
			if !f.IsSymlink {
				cf, cb, cm := vfs.subtreeFileStatsLocked(childPath)
				files += cf
				bytes += cb
				if cm > modTime {
					modTime = cm
				}
			}
			continue
		}
		files++
		bytes += f.Size
		if f.LastModified > modTime {
			modTime = f.LastModified
		}
	}
	return files, bytes, modTime
}

// FindChildFoldMatch returns the base name of the first direct child of
// parentPath whose name case-folds to one of candidates, plus the index of the
// matched candidate. It walks the children index directly (no directory-listing
// allocation), so releaseguard's per-MKD dupe/case/nuked check is a tight map
// scan under a read lock instead of building and copying the whole section.
func (vfs *VirtualFileSystem) FindChildFoldMatch(parentPath string, candidates []string) (string, int, bool) {
	if len(candidates) == 0 {
		return "", 0, false
	}
	parentPath = cleanVFSPath(parentPath)
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	for childPath := range vfs.children[parentPath] {
		base := pathpkg.Base(childPath)
		for i, cand := range candidates {
			if strings.EqualFold(base, cand) {
				return base, i, true
			}
		}
	}
	return "", 0, false
}

// Count returns the number of entries in the VFS
func (vfs *VirtualFileSystem) Count() int {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	return len(vfs.files)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SaveToDisk persists the VFS to a gob file.
// Called on shutdown and periodically by the slave manager.
func (vfs *VirtualFileSystem) SaveToDisk(filePath string) error {
	vfs.mu.RLock()
	version := vfs.persistVersion
	if version == vfs.savedVersion {
		vfs.mu.RUnlock()
		return nil
	}
	snapshot := vfsSnapshot{
		Files:   make(map[string]*VFSFile, len(vfs.files)),
		DirMeta: make(map[string]*VFSDirMeta, len(vfs.dirMeta)),
	}
	for path, file := range vfs.files {
		if file == nil {
			continue
		}
		copyFile := *file
		snapshot.Files[path] = &copyFile
	}
	for dirPath, meta := range vfs.dirMeta {
		if meta == nil {
			continue
		}
		snapshot.DirMeta[dirPath] = copyVFSDirMeta(meta)
	}
	vfs.mu.RUnlock()

	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create vfs dir: %w", err)
		}
	}

	// Write to a unique temp file in the same directory, then rename atomically.
	tmpPattern := filepath.Base(filePath) + ".*.tmp"
	f, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return fmt.Errorf("create vfs file: %w", err)
	}
	tmpPath := f.Name()

	enc := gob.NewEncoder(f)
	if err := enc.Encode(snapshot); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("encode vfs: %w", err)
	}
	f.Close()

	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("rename vfs file: %w", err)
	}

	vfs.mu.Lock()
	if version > vfs.savedVersion {
		vfs.savedVersion = version
	}
	vfs.mu.Unlock()

	log.Printf("[VFS] Saved %d entries to %s", len(snapshot.Files), filePath)
	return nil
}

// LoadFromDisk loads the VFS from a previously saved gob file.
// Called on master startup before slaves connect.
func (vfs *VirtualFileSystem) LoadFromDisk(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[VFS] No saved VFS at %s, starting fresh", filePath)
			return nil
		}
		return fmt.Errorf("open vfs file: %w", err)
	}
	defer f.Close()

	vfs.mu.Lock()
	defer vfs.mu.Unlock()

	dec := gob.NewDecoder(f)
	var snapshot vfsSnapshot
	if err := dec.Decode(&snapshot); err != nil {
		if _, seekErr := f.Seek(0, 0); seekErr != nil {
			return fmt.Errorf("decode vfs: %w", err)
		}
		dec = gob.NewDecoder(f)
		var legacyFiles map[string]*VFSFile
		if legacyErr := dec.Decode(&legacyFiles); legacyErr != nil {
			return fmt.Errorf("decode vfs: %w", err)
		}
		vfs.files = legacyFiles
		vfs.dirMeta = make(map[string]*VFSDirMeta)
	} else {
		vfs.files = snapshot.Files
		if snapshot.DirMeta != nil {
			vfs.dirMeta = snapshot.DirMeta
		} else {
			vfs.dirMeta = make(map[string]*VFSDirMeta)
		}
	}

	// Ensure root exists
	if _, ok := vfs.files["/"]; !ok {
		vfs.files["/"] = &VFSFile{Path: "/", IsDir: true, Seen: true}
	}
	if vfs.dirMeta == nil {
		vfs.dirMeta = make(map[string]*VFSDirMeta)
	}
	if vfs.protectedDirs == nil {
		vfs.protectedDirs = make(map[string]bool)
	}
	if vfs.hiddenPaths == nil {
		vfs.hiddenPaths = make(map[string]bool)
	}
	if vfs.excludePaths == nil {
		vfs.excludePaths = make(map[string]bool)
	}
	vfs.pruneExcludedPathsLocked()
	vfs.pruneHiddenPathsLocked()
	vfs.rebuildChildrenLocked()
	vfs.persistVersion = 0
	vfs.savedVersion = 0

	log.Printf("[VFS] Loaded %d entries from %s", len(vfs.files), filePath)
	return nil
}

func (vfs *VirtualFileSystem) isHiddenPathLocked(p string) bool {
	p = cleanVFSPath(p)
	if p == "/" || p == "" {
		return false
	}
	for hidden := range vfs.hiddenPaths {
		if p == hidden || strings.HasPrefix(p, hidden+"/") {
			return true
		}
	}
	return false
}

func (vfs *VirtualFileSystem) isExcludedPathLocked(p string) bool {
	p = cleanVFSPath(p)
	if p == "/" || p == "" {
		return false
	}
	for excluded := range vfs.excludePaths {
		if p == excluded || strings.HasPrefix(p, excluded+"/") {
			return true
		}
	}
	return false
}

func (vfs *VirtualFileSystem) IsExcludedPath(p string) bool {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	return vfs.isExcludedPathLocked(p)
}

func (vfs *VirtualFileSystem) pruneExcludedPathsLocked() {
	changed := false
	for p := range vfs.files {
		if vfs.isExcludedPathLocked(p) {
			vfs.deleteFileEntryOnlyLocked(p)
			delete(vfs.dirMeta, p)
			changed = true
		}
	}
	if changed {
		vfs.rebuildChildrenLocked()
		vfs.markPersistDirtyLocked()
	}
}

func (vfs *VirtualFileSystem) pruneHiddenPathsLocked() {
	changed := false
	for p := range vfs.files {
		if vfs.isHiddenPathLocked(p) {
			vfs.deleteFileEntryOnlyLocked(p)
			delete(vfs.dirMeta, p)
			changed = true
		}
	}
	if changed {
		vfs.rebuildChildrenLocked()
		vfs.markPersistDirtyLocked()
	}
}

func cleanVFSPath(p string) string {
	// Root BEFORE cleaning so relative ".." input collapses against "/"
	// (path.Clean("/foo/../../bar") == "/bar") instead of surviving as an
	// alias key like "/../bar" that no lookup will ever match.
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	if p == "" || p == "." {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return pathpkg.Clean(p)
}

// SetSFVData caches parsed SFV entries on a directory.
func (vfs *VirtualFileSystem) SetSFVData(dirPath string, sfvName string, entries map[string]uint32) {
	vfs.setSFVData(dirPath, sfvName, 0, entries, true)
}

// SetSFVDataWithChecksum caches parsed SFV entries plus the checksum of the
// SFV file itself. The checksum lets stale metadata be ignored if the .sfv in
// the current VFS no longer matches the parse result.
func (vfs *VirtualFileSystem) SetSFVDataWithChecksum(dirPath string, sfvName string, sfvChecksum uint32, entries map[string]uint32) {
	vfs.setSFVData(dirPath, sfvName, sfvChecksum, entries, false)
}

func (vfs *VirtualFileSystem) setSFVData(dirPath string, sfvName string, sfvChecksum uint32, entries map[string]uint32, allowWithoutFile bool) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()
	dirPath = cleanVFSPath(dirPath)
	normalized := make(map[string]uint32, len(entries))
	for name, crc := range entries {
		name = raceFileKey(name)
		if name != "" {
			normalized[name] = crc
		}
	}
	meta := vfs.dirMeta[dirPath]
	if meta == nil {
		meta = &VFSDirMeta{}
		vfs.dirMeta[dirPath] = meta
	}
	meta.SFVEntries = normalized
	meta.SFVName = strings.TrimSpace(pathpkg.Base(sfvName))
	meta.SFVChecksum = sfvChecksum
	meta.SFVAllowWithoutFile = allowWithoutFile
	vfs.invalidateRaceCacheLocked(dirPath)
	vfs.markPersistDirtyLocked()
}

// GetSFVData returns cached SFV entries for a directory, or nil if not cached.
func (vfs *VirtualFileSystem) GetSFVData(dirPath string) *VFSDirMeta {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if !vfs.sfvMetaValidLocked(dirPath, meta) {
		return nil
	}
	return copyVFSDirMeta(meta)
}

func (vfs *VirtualFileSystem) CacheZipExpectedParts(dirPath string, expected int, dizChecksum uint32) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()
	dirPath = cleanVFSPath(dirPath)
	if expected <= 0 {
		if meta := vfs.dirMeta[dirPath]; meta != nil {
			meta.ZipExpectedParts = 0
			meta.ZipDIZChecksum = 0
			vfs.invalidateRaceCacheLocked(dirPath)
			if meta.SFVEntries == nil && len(meta.RequestEntries) == 0 && len(meta.RequestFillEntries) == 0 {
				delete(vfs.dirMeta, dirPath)
			}
			vfs.markPersistDirtyLocked()
		}
		return
	}
	meta := vfs.dirMeta[dirPath]
	if meta == nil {
		meta = &VFSDirMeta{}
		vfs.dirMeta[dirPath] = meta
	}
	meta.ZipExpectedParts = expected
	meta.ZipDIZChecksum = dizChecksum
	vfs.invalidateRaceCacheLocked(dirPath)
	vfs.markPersistDirtyLocked()
}

func (vfs *VirtualFileSystem) clearZipMetaLocked(dirPath string) {
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if meta == nil {
		return
	}
	meta.ZipExpectedParts = 0
	meta.ZipDIZChecksum = 0
	vfs.invalidateRaceCacheLocked(dirPath)
	if meta.SFVEntries == nil && len(meta.RequestEntries) == 0 && len(meta.RequestFillEntries) == 0 {
		delete(vfs.dirMeta, dirPath)
	}
}

func (vfs *VirtualFileSystem) GetZipExpectedParts(dirPath string) (int, bool) {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	return vfs.getZipExpectedPartsLocked(dirPath)
}

func (vfs *VirtualFileSystem) SetRequestData(dirPath string, requests []plugin.RequestRecord, fills []plugin.RequestFillRecord) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if meta == nil {
		meta = &VFSDirMeta{}
		vfs.dirMeta[dirPath] = meta
	}
	meta.RequestEntries = append([]plugin.RequestRecord(nil), requests...)
	meta.RequestFillEntries = append([]plugin.RequestFillRecord(nil), fills...)
	vfs.markPersistDirtyLocked()
}

func (vfs *VirtualFileSystem) GetRequestData(dirPath string) ([]plugin.RequestRecord, []plugin.RequestFillRecord) {
	vfs.mu.RLock()
	defer vfs.mu.RUnlock()
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if meta == nil {
		return nil, nil
	}
	requests := append([]plugin.RequestRecord(nil), meta.RequestEntries...)
	fills := append([]plugin.RequestFillRecord(nil), meta.RequestFillEntries...)
	return requests, fills
}

func (vfs *VirtualFileSystem) getZipExpectedPartsLocked(dirPath string) (int, bool) {
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if meta == nil || meta.ZipExpectedParts <= 0 {
		return 0, false
	}
	dizPath := cleanVFSPath(pathpkg.Join(dirPath, "file_id.diz"))
	dizFile := vfs.files[dizPath]
	if dizFile == nil || dizFile.IsDir || dizFile.IsSymlink {
		return 0, false
	}
	if checksumKnownMismatch(meta.ZipDIZChecksum, dizFile.Checksum) {
		return 0, false
	}
	if !vfs.hasZipArchiveLocked(dirPath) {
		return 0, false
	}
	return meta.ZipExpectedParts, true
}

// RaceUserStat holds per-user race statistics computed from VFS.
type RaceUserStat struct {
	Name       string
	Group      string
	Files      int
	Bytes      int64
	Speed      float64 // bytes/sec average of this user's per-file speeds (pzs-ng style)
	PeakSpeed  float64 // bytes/sec of this user's fastest single file
	SlowSpeed  float64 // bytes/sec of this user's slowest single file
	Percent    int
	DurationMs int64 // sum of file durations for this user
}

// RaceGroupStat holds per-group race statistics.
type RaceGroupStat struct {
	Name    string
	Files   int
	Bytes   int64
	Speed   float64 // bytes/sec sum of user speeds in this group (gl/pzs-style grouptop feel)
	Percent int
}

// GetRaceStats computes race statistics for a directory from VFS metadata.
// Like drftpd's SFVTools.getSFVFiles + RankUtils.userSort.
func (vfs *VirtualFileSystem) GetRaceStats(dirPath string) (users []RaceUserStat, groups []RaceGroupStat, totalBytes int64, present int, total int) {
	return vfs.GetRaceStatsFiltered(dirPath, nil)
}

// GetRaceStatsFiltered computes race stats directly from VFS state.
func (vfs *VirtualFileSystem) GetRaceStatsFiltered(dirPath string, excludeKeys map[string]bool) (users []RaceUserStat, groups []RaceGroupStat, totalBytes int64, present int, total int) {
	dirPath = cleanVFSPath(dirPath)
	if len(excludeKeys) == 0 {
		vfs.mu.RLock()
		cache := vfs.cachedRaceStateLocked(dirPath)
		if cache != nil {
			users = append(users, cache.Users...)
			groups = append(groups, cache.Groups...)
			totalBytes = cache.TotalBytes
			present = cache.Present
			total = cache.Total
			vfs.mu.RUnlock()
			return
		}
		// Cache miss: compute under the READ lock, like the filtered path below.
		// The compute is read-only. Holding the global WRITE lock here used to
		// freeze every other VFS op (CWD/ResolvePath, other listings) for the
		// whole computation, and since the race cache is invalidated on every
		// upload, that serialized the entire VFS during a race. Readers don't
		// block each other, so concurrent recompute is fine.
		computeVersion := vfs.persistVersion
		cache = vfs.computeRaceStateFilteredLocked(dirPath, nil)
		vfs.mu.RUnlock()
		if cache != nil {
			users = append(users, cache.Users...)
			groups = append(groups, cache.Groups...)
			totalBytes = cache.TotalBytes
			present = cache.Present
			total = cache.Total
			// Publish for the next reader with a brief write lock: just a pointer
			// store, never held across the computation. If any VFS write happened
			// after our read-lock snapshot, skip publishing to avoid caching stale
			// stats.
			vfs.mu.Lock()
			if meta := vfs.dirMeta[dirPath]; vfs.persistVersion == computeVersion && meta != nil && meta.raceCache == nil && vfs.sfvMetaValidLocked(dirPath, meta) {
				meta.raceCache = cloneRaceCache(cache)
			}
			vfs.mu.Unlock()
		}
		return
	}

	vfs.mu.RLock()
	cache := vfs.computeRaceStateFilteredLocked(dirPath, excludeKeys)
	if cache == nil {
		vfs.mu.RUnlock()
		return
	}
	users = append(users, cache.Users...)
	groups = append(groups, cache.Groups...)
	totalBytes = cache.TotalBytes
	present = cache.Present
	total = cache.Total
	vfs.mu.RUnlock()
	return
}

// GetZipRaceStats computes ZIP release stats directly from observed ZIP payloads.
func (vfs *VirtualFileSystem) GetZipRaceStats(dirPath string) (users []RaceUserStat, groups []RaceGroupStat, totalBytes int64, present int, total int) {
	return vfs.GetZipRaceStatsFiltered(dirPath, nil)
}

// GetZipRaceStatsFiltered computes ZIP release stats, excluding currently open payloads.
func (vfs *VirtualFileSystem) GetZipRaceStatsFiltered(dirPath string, excludeKeys map[string]bool) (users []RaceUserStat, groups []RaceGroupStat, totalBytes int64, present int, total int) {
	dirPath = cleanVFSPath(dirPath)
	if len(excludeKeys) == 0 {
		vfs.mu.RLock()
		cache := vfs.cachedZipRaceStateLocked(dirPath)
		if cache != nil {
			users = append(users, cache.Users...)
			groups = append(groups, cache.Groups...)
			totalBytes = cache.TotalBytes
			present = cache.Present
			total = cache.Total
			vfs.mu.RUnlock()
			return
		}
		// Cache miss: compute under the READ lock (the filtered ZIP path below
		// already does, so the compute is read-only). Avoids taking the global
		// write lock per miss, which serialized the VFS during races.
		computeVersion := vfs.persistVersion
		cache = vfs.computeZipRaceStateFilteredLocked(dirPath, nil)
		vfs.mu.RUnlock()
		if cache != nil {
			users = append(users, cache.Users...)
			groups = append(groups, cache.Groups...)
			totalBytes = cache.TotalBytes
			present = cache.Present
			total = cache.Total
			vfs.mu.Lock()
			if meta := vfs.dirMeta[dirPath]; vfs.persistVersion == computeVersion && meta != nil && meta.zipRaceCache == nil {
				meta.zipRaceCache = cloneRaceCache(cache)
			}
			vfs.mu.Unlock()
		}
		return
	}

	vfs.mu.RLock()
	cache := vfs.computeZipRaceStateFilteredLocked(dirPath, excludeKeys)
	if cache == nil {
		vfs.mu.RUnlock()
		return
	}
	users = append(users, cache.Users...)
	groups = append(groups, cache.Groups...)
	totalBytes = cache.TotalBytes
	present = cache.Present
	total = cache.Total
	vfs.mu.RUnlock()
	return
}

func raceFileKey(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	name = strings.TrimPrefix(name, "\ufeff")
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	name = strings.TrimPrefix(strings.TrimSpace(name), "\ufeff")
	return strings.ToLower(name)
}

func (vfs *VirtualFileSystem) cachedRaceStateLocked(dirPath string) *VFSRaceCache {
	meta := vfs.dirMeta[dirPath]
	if !vfs.sfvMetaValidLocked(dirPath, meta) {
		return nil
	}
	return cloneRaceCache(meta.raceCache)
}

func (vfs *VirtualFileSystem) cachedZipRaceStateLocked(dirPath string) *VFSRaceCache {
	meta := vfs.dirMeta[dirPath]
	if meta == nil {
		return nil
	}
	return cloneRaceCache(meta.zipRaceCache)
}

func cloneRaceCache(cache *VFSRaceCache) *VFSRaceCache {
	if cache == nil {
		return nil
	}
	out := *cache
	if len(cache.Users) > 0 {
		out.Users = append([]RaceUserStat(nil), cache.Users...)
	}
	if len(cache.Groups) > 0 {
		out.Groups = append([]RaceGroupStat(nil), cache.Groups...)
	}
	return &out
}

func (vfs *VirtualFileSystem) ensureChildrenBucketLocked(dirPath string) {
	dirPath = cleanVFSPath(dirPath)
	if vfs.children == nil {
		vfs.children = make(map[string]map[string]struct{})
	}
	if _, ok := vfs.children[dirPath]; !ok {
		vfs.children[dirPath] = make(map[string]struct{})
	}
}

func (vfs *VirtualFileSystem) ensureSlavePathIndexLocked() {
	if vfs.slavePaths == nil {
		vfs.slavePaths = make(map[string]map[string]struct{})
	}
}

func (vfs *VirtualFileSystem) addSlavePathLocked(slaveName, path string) {
	slaveName = strings.TrimSpace(slaveName)
	if slaveName == "" {
		return
	}
	vfs.ensureSlavePathIndexLocked()
	path = cleanVFSPath(path)
	paths := vfs.slavePaths[slaveName]
	if paths == nil {
		paths = make(map[string]struct{})
		vfs.slavePaths[slaveName] = paths
	}
	paths[path] = struct{}{}
}

func (vfs *VirtualFileSystem) removeSlavePathLocked(slaveName, path string) {
	slaveName = strings.TrimSpace(slaveName)
	if slaveName == "" || vfs.slavePaths == nil {
		return
	}
	path = cleanVFSPath(path)
	paths := vfs.slavePaths[slaveName]
	if paths == nil {
		return
	}
	delete(paths, path)
	if len(paths) == 0 {
		delete(vfs.slavePaths, slaveName)
	}
}

func (vfs *VirtualFileSystem) reindexSlavePathLocked(path, oldSlave, newSlave string) {
	path = cleanVFSPath(path)
	oldSlave = strings.TrimSpace(oldSlave)
	newSlave = strings.TrimSpace(newSlave)
	if oldSlave == newSlave {
		if newSlave != "" {
			vfs.addSlavePathLocked(newSlave, path)
		}
		return
	}
	vfs.removeSlavePathLocked(oldSlave, path)
	vfs.addSlavePathLocked(newSlave, path)
}

func (vfs *VirtualFileSystem) deleteFileEntryOnlyLocked(path string) {
	path = cleanVFSPath(path)
	if file := vfs.files[path]; file != nil {
		vfs.removeSlavePathLocked(file.SlaveName, path)
	}
	delete(vfs.files, path)
}

func (vfs *VirtualFileSystem) rebuildSlavePathsLocked() {
	vfs.slavePaths = make(map[string]map[string]struct{})
	for path, file := range vfs.files {
		if file == nil {
			continue
		}
		vfs.addSlavePathLocked(file.SlaveName, path)
	}
}

func (vfs *VirtualFileSystem) pathsForSlaveLocked(slaveName string) []string {
	slaveName = strings.TrimSpace(slaveName)
	if slaveName == "" {
		return nil
	}
	if vfs.slavePaths == nil {
		vfs.rebuildSlavePathsLocked()
	}
	paths := vfs.slavePaths[slaveName]
	out := make([]string, 0, len(paths))
	for path := range paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func (vfs *VirtualFileSystem) linkChildLocked(parentPath, childPath string) {
	parentPath = cleanVFSPath(parentPath)
	childPath = cleanVFSPath(childPath)
	vfs.ensureChildrenBucketLocked(parentPath)
	vfs.children[parentPath][childPath] = struct{}{}
}

func (vfs *VirtualFileSystem) ensureParentDirsLocked(path string, slaveName string) {
	path = cleanVFSPath(path)
	if _, ok := vfs.files["/"]; !ok {
		vfs.files["/"] = &VFSFile{Path: "/", IsDir: true, Seen: true}
	}
	vfs.ensureChildrenBucketLocked("/")

	dir := cleanVFSPath(pathpkg.Dir(path))
	for dir != "." && dir != "" {
		if existing, exists := vfs.files[dir]; !exists {
			vfs.files[dir] = &VFSFile{
				Path:      dir,
				IsDir:     true,
				SlaveName: slaveName,
				Seen:      true,
			}
			vfs.addSlavePathLocked(slaveName, dir)
		} else {
			cp := *existing
			cp.Path = dir
			cp.IsDir = true
			cp.Seen = true
			vfs.files[dir] = &cp
		}
		vfs.ensureChildrenBucketLocked(dir)
		if dir == "/" {
			break
		}
		parent := cleanVFSPath(pathpkg.Dir(dir))
		vfs.linkChildLocked(parent, dir)
		dir = parent
	}
}

func (vfs *VirtualFileSystem) moveSubtreeLocked(from, to, newSlaveName string) bool {
	from = cleanVFSPath(from)
	to = cleanVFSPath(to)
	paths := vfs.collectSubtreePathsLocked(from)
	if len(paths) == 0 || vfs.files[from] == nil {
		return false
	}

	type moveEntry struct {
		oldPath string
		newPath string
		file    *VFSFile
		meta    *VFSDirMeta
	}
	moves := make([]moveEntry, 0, len(paths))
	for _, oldPath := range paths {
		file := vfs.files[oldPath]
		if file == nil {
			continue
		}
		suffix := strings.TrimPrefix(oldPath, from)
		newPath := cleanVFSPath(to + suffix)
		moves = append(moves, moveEntry{
			oldPath: oldPath,
			newPath: newPath,
			file:    file,
			meta:    vfs.dirMeta[oldPath],
		})
	}
	if len(moves) == 0 {
		return false
	}

	fromParent := cleanVFSPath(pathpkg.Dir(from))
	if children := vfs.children[fromParent]; children != nil {
		delete(children, from)
	}
	for _, mv := range moves {
		vfs.deleteFileEntryOnlyLocked(mv.oldPath)
		delete(vfs.children, mv.oldPath)
		if mv.meta != nil {
			delete(vfs.dirMeta, mv.oldPath)
		}
	}

	slaveForParents := moves[0].file.SlaveName
	if strings.TrimSpace(newSlaveName) != "" {
		slaveForParents = newSlaveName
	}
	vfs.ensureParentDirsLocked(to, slaveForParents)
	for _, mv := range moves {
		cp := *mv.file
		cp.Path = mv.newPath
		if strings.TrimSpace(newSlaveName) != "" {
			cp.SlaveName = newSlaveName
		}
		vfs.files[mv.newPath] = &cp
		vfs.addSlavePathLocked(cp.SlaveName, mv.newPath)
		if cp.IsDir {
			vfs.ensureChildrenBucketLocked(mv.newPath)
		}
		vfs.linkChildLocked(cleanVFSPath(pathpkg.Dir(mv.newPath)), mv.newPath)
		if mv.meta != nil {
			vfs.dirMeta[mv.newPath] = mv.meta
		}
		vfs.invalidateRaceCachesForPathLocked(mv.oldPath)
		vfs.invalidateRaceCachesForPathLocked(mv.newPath)
	}
	return true
}

func (vfs *VirtualFileSystem) touchAncestorsLocked(path string, ts int64) {
	if ts <= 0 {
		ts = time.Now().Unix()
	}
	current := cleanVFSPath(path)
	for current != "." && current != "" {
		if f := vfs.files[current]; f != nil && f.IsDir && ts > f.LastModified {
			cp := *f
			cp.LastModified = ts
			vfs.files[current] = &cp
		}
		if current == "/" {
			break
		}
		current = cleanVFSPath(pathpkg.Dir(current))
	}
}

func (vfs *VirtualFileSystem) rebuildChildrenLocked() {
	if vfs.files == nil {
		vfs.files = make(map[string]*VFSFile)
	}
	vfs.slavePaths = make(map[string]map[string]struct{})
	if _, ok := vfs.files["/"]; !ok {
		vfs.files["/"] = &VFSFile{Path: "/", IsDir: true, Seen: true}
	}

	for path, file := range vfs.files {
		if file == nil {
			vfs.deleteFileEntryOnlyLocked(path)
			continue
		}
		cleanPath := cleanVFSPath(path)
		if cleanPath != path {
			delete(vfs.files, path)
			if _, exists := vfs.files[cleanPath]; !exists {
				file.Path = cleanPath
				vfs.files[cleanPath] = file
			}
			continue
		}
		file.Path = cleanPath
	}

	paths := make([]string, 0, len(vfs.files))
	for path := range vfs.files {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		di := strings.Count(paths[i], "/")
		dj := strings.Count(paths[j], "/")
		if di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})
	for _, path := range paths {
		file := vfs.files[path]
		if file == nil {
			continue
		}
		vfs.ensureParentDirsLocked(path, file.SlaveName)
	}

	children := make(map[string]map[string]struct{})
	for path, file := range vfs.files {
		if file != nil && file.IsDir {
			children[path] = make(map[string]struct{})
		}
	}
	if _, ok := children["/"]; !ok {
		children["/"] = make(map[string]struct{})
	}
	for path := range vfs.files {
		if path == "/" {
			continue
		}
		parent := cleanVFSPath(pathpkg.Dir(path))
		if _, ok := children[parent]; !ok {
			children[parent] = make(map[string]struct{})
		}
		children[parent][path] = struct{}{}
	}
	vfs.children = children
	vfs.rebuildSlavePathsLocked()
	vfs.clearAllRaceCachesLocked()
}

func (vfs *VirtualFileSystem) computeRaceStateFilteredLocked(dirPath string, excludeKeys map[string]bool) *VFSRaceCache {
	dirPath = cleanVFSPath(dirPath)
	meta := vfs.dirMeta[dirPath]
	if !vfs.sfvMetaValidLocked(dirPath, meta) {
		return nil
	}

	t0 := time.Now()
	defer func() {
		metrics.RaceComputes.Inc()
		metrics.RaceComputeTime.Observe(time.Since(t0))
	}()

	userMap := make(map[string]*RaceUserStat)
	groupMap := make(map[string]*RaceGroupStat)
	userStartMs := make(map[string]int64)
	userEndMs := make(map[string]int64)
	presentFiles := make(map[string]*VFSFile)
	for childPath := range vfs.children[dirPath] {
		f := vfs.files[childPath]
		if f == nil || f.IsDir {
			continue
		}
		presentFiles[raceFileKey(pathpkg.Base(childPath))] = f
	}

	cache := &VFSRaceCache{
		Total: len(meta.SFVEntries),
	}
	for sfvFile, expectedCRC := range meta.SFVEntries {
		key := raceFileKey(sfvFile)
		f := presentFiles[key]
		if f == nil {
			continue
		}
		if !isChecksumVerified(expectedCRC, f.Checksum) {
			// Not yet CRC-verified: skip an in-progress / unverifiable file, whether
			// or not a live-stat lists it as uploading.
			continue
		}
		// CRC-verified means the file has fully completed, so count it even if a
		// lagging live-stat still lists it in excludeKeys ("uploading"). Otherwise
		// completeness flaps false at the instant the last file lands -- which would
		// lose the COMPLETE announce -- and a duplicate re-upload of an already-good
		// file would wrongly un-complete the release.
		cache.Present++
		cache.TotalBytes += f.Size

		if f.XferTime <= 0 {
			continue
		}

		owner := f.Owner
		if owner == "" {
			owner = "unknown"
		}
		group := f.Group
		if group == "" {
			group = "NoGroup"
		}

		us := userMap[owner]
		if us == nil {
			us = &RaceUserStat{Name: owner, Group: group}
			userMap[owner] = us
		}
		us.Files++
		us.Bytes += f.Size
		fileSpeed := float64(f.Size) / (float64(f.XferTime) / 1000.0)
		if fileSpeed > us.PeakSpeed {
			us.PeakSpeed = fileSpeed
		}
		if us.SlowSpeed == 0 || fileSpeed < us.SlowSpeed {
			us.SlowSpeed = fileSpeed
		}
		us.DurationMs += f.XferTime
		fileEndMs := f.LastModified * 1000
		if fileEndMs <= 0 {
			fileEndMs = time.Now().UnixMilli()
		}
		fileStartMs := fileEndMs - f.XferTime
		if fileStartMs < 0 {
			fileStartMs = 0
		}
		if start := userStartMs[owner]; start == 0 || fileStartMs < start {
			userStartMs[owner] = fileStartMs
		}
		if fileEndMs > userEndMs[owner] {
			userEndMs[owner] = fileEndMs
		}

		gs := groupMap[group]
		if gs == nil {
			gs = &RaceGroupStat{Name: group}
			groupMap[group] = gs
		}
		gs.Files++
		gs.Bytes += f.Size
	}

	cache.Users = make([]RaceUserStat, 0, len(userMap))
	for _, us := range userMap {
		// Per-user speed = combined throughput over the racer's active span
		// (first file start -> last file end). Parallel upload slots overlap, so
		// this reflects ALL slots combined: the high per-user number glftpd
		// shows. Sum of per-file transfer time is only a fallback.
		if startMs, endMs := userStartMs[us.Name], userEndMs[us.Name]; us.Bytes > 0 && endMs > startMs {
			us.Speed = float64(us.Bytes) / (float64(endMs-startMs) / 1000.0)
		} else if us.Bytes > 0 && us.DurationMs > 0 {
			us.Speed = float64(us.Bytes) / (float64(us.DurationMs) / 1000.0)
		}
		if cache.Total > 0 {
			us.Percent = (us.Files * 100) / cache.Total
		}
		cache.Users = append(cache.Users, *us)
	}
	sort.Slice(cache.Users, func(i, j int) bool {
		if cache.Users[i].Bytes != cache.Users[j].Bytes {
			return cache.Users[i].Bytes > cache.Users[j].Bytes
		}
		if cache.Users[i].Files != cache.Users[j].Files {
			return cache.Users[i].Files > cache.Users[j].Files
		}
		return strings.ToLower(cache.Users[i].Name) < strings.ToLower(cache.Users[j].Name)
	})

	cache.Groups = make([]RaceGroupStat, 0, len(groupMap))
	for _, gs := range groupMap {
		if cache.Total > 0 {
			gs.Percent = (gs.Files * 100) / cache.Total
		}
		// Group speed = sum of its racers' combined throughputs.
		for _, us := range cache.Users {
			if us.Group == gs.Name {
				gs.Speed += us.Speed
			}
		}
		cache.Groups = append(cache.Groups, *gs)
	}
	sort.Slice(cache.Groups, func(i, j int) bool {
		if cache.Groups[i].Bytes != cache.Groups[j].Bytes {
			return cache.Groups[i].Bytes > cache.Groups[j].Bytes
		}
		if cache.Groups[i].Files != cache.Groups[j].Files {
			return cache.Groups[i].Files > cache.Groups[j].Files
		}
		return strings.ToLower(cache.Groups[i].Name) < strings.ToLower(cache.Groups[j].Name)
	})

	return cache
}

func (vfs *VirtualFileSystem) computeZipRaceStateFilteredLocked(dirPath string, excludeKeys map[string]bool) *VFSRaceCache {
	dirPath = cleanVFSPath(dirPath)
	userMap := make(map[string]*RaceUserStat)
	groupMap := make(map[string]*RaceGroupStat)
	userStartMs := make(map[string]int64)
	userEndMs := make(map[string]int64)

	cache := &VFSRaceCache{}
	if expected, ok := vfs.getZipExpectedPartsLocked(dirPath); ok && expected > 0 {
		cache.Total = expected
	}
	for childPath := range vfs.children[dirPath] {
		f := vfs.files[childPath]
		if f == nil || f.IsDir || f.IsSymlink {
			continue
		}
		name := strings.TrimSpace(pathpkg.Base(childPath))
		if strings.HasPrefix(name, ".") || !zipscript.IsZipPayloadName(name) {
			continue
		}
		if excludeKeys[raceFileKey(name)] {
			continue
		}
		cache.Present++
		cache.TotalBytes += f.Size

		if f.XferTime <= 0 {
			continue
		}
		owner := f.Owner
		if owner == "" {
			owner = "unknown"
		}
		group := f.Group
		if group == "" {
			group = "NoGroup"
		}

		us := userMap[owner]
		if us == nil {
			us = &RaceUserStat{Name: owner, Group: group}
			userMap[owner] = us
		}
		us.Files++
		us.Bytes += f.Size
		fileSpeed := float64(f.Size) / (float64(f.XferTime) / 1000.0)
		if fileSpeed > us.PeakSpeed {
			us.PeakSpeed = fileSpeed
		}
		if us.SlowSpeed == 0 || fileSpeed < us.SlowSpeed {
			us.SlowSpeed = fileSpeed
		}
		us.DurationMs += f.XferTime
		fileEndMs := f.LastModified * 1000
		if fileEndMs <= 0 {
			fileEndMs = time.Now().UnixMilli()
		}
		fileStartMs := fileEndMs - f.XferTime
		if fileStartMs < 0 {
			fileStartMs = 0
		}
		if start := userStartMs[owner]; start == 0 || fileStartMs < start {
			userStartMs[owner] = fileStartMs
		}
		if fileEndMs > userEndMs[owner] {
			userEndMs[owner] = fileEndMs
		}

		gs := groupMap[group]
		if gs == nil {
			gs = &RaceGroupStat{Name: group}
			groupMap[group] = gs
		}
		gs.Files++
		gs.Bytes += f.Size
	}
	if cache.Present == 0 && cache.Total == 0 {
		return nil
	}
	if cache.Total < cache.Present {
		cache.Total = cache.Present
	}

	cache.Users = make([]RaceUserStat, 0, len(userMap))
	for _, us := range userMap {
		// Per-user speed = combined throughput over the racer's active span
		// (first file start -> last file end). Parallel upload slots overlap, so
		// this reflects ALL slots combined: the high per-user number glftpd
		// shows. Sum of per-file transfer time is only a fallback.
		if startMs, endMs := userStartMs[us.Name], userEndMs[us.Name]; us.Bytes > 0 && endMs > startMs {
			us.Speed = float64(us.Bytes) / (float64(endMs-startMs) / 1000.0)
		} else if us.Bytes > 0 && us.DurationMs > 0 {
			us.Speed = float64(us.Bytes) / (float64(us.DurationMs) / 1000.0)
		}
		if cache.Total > 0 {
			us.Percent = (us.Files * 100) / cache.Total
		}
		cache.Users = append(cache.Users, *us)
	}
	sort.Slice(cache.Users, func(i, j int) bool {
		if cache.Users[i].Bytes != cache.Users[j].Bytes {
			return cache.Users[i].Bytes > cache.Users[j].Bytes
		}
		if cache.Users[i].Files != cache.Users[j].Files {
			return cache.Users[i].Files > cache.Users[j].Files
		}
		return strings.ToLower(cache.Users[i].Name) < strings.ToLower(cache.Users[j].Name)
	})

	cache.Groups = make([]RaceGroupStat, 0, len(groupMap))
	for _, gs := range groupMap {
		if cache.Total > 0 {
			gs.Percent = (gs.Files * 100) / cache.Total
		}
		// Group speed = sum of its racers' combined throughputs.
		for _, us := range cache.Users {
			if us.Group == gs.Name {
				gs.Speed += us.Speed
			}
		}
		cache.Groups = append(cache.Groups, *gs)
	}
	sort.Slice(cache.Groups, func(i, j int) bool {
		if cache.Groups[i].Bytes != cache.Groups[j].Bytes {
			return cache.Groups[i].Bytes > cache.Groups[j].Bytes
		}
		if cache.Groups[i].Files != cache.Groups[j].Files {
			return cache.Groups[i].Files > cache.Groups[j].Files
		}
		return strings.ToLower(cache.Groups[i].Name) < strings.ToLower(cache.Groups[j].Name)
	})

	return cache
}

func (vfs *VirtualFileSystem) sfvMetaValidLocked(dirPath string, meta *VFSDirMeta) bool {
	if meta == nil || len(meta.SFVEntries) == 0 {
		return false
	}
	sfvName := strings.TrimSpace(meta.SFVName)
	if sfvName == "" {
		return false
	}
	sfvPath := cleanVFSPath(pathpkg.Join(dirPath, pathpkg.Base(sfvName)))
	sfvFile := vfs.files[sfvPath]
	if sfvFile == nil || sfvFile.IsDir || sfvFile.IsSymlink {
		return meta.SFVAllowWithoutFile
	}
	if checksumKnownMismatch(meta.SFVChecksum, sfvFile.Checksum) {
		return false
	}
	return true
}

func (vfs *VirtualFileSystem) zipPayloadCountLocked(dirPath string) int {
	dirPath = cleanVFSPath(dirPath)
	total := 0
	for childPath := range vfs.children[dirPath] {
		f := vfs.files[childPath]
		if f == nil || f.IsDir || f.IsSymlink {
			continue
		}
		name := strings.TrimSpace(pathpkg.Base(childPath))
		if strings.HasPrefix(name, ".") || !zipscript.IsZipPayloadName(name) {
			continue
		}
		total++
	}
	return total
}

func (vfs *VirtualFileSystem) hasZipArchiveLocked(dirPath string) bool {
	dirPath = cleanVFSPath(dirPath)
	for childPath := range vfs.children[dirPath] {
		f := vfs.files[childPath]
		if f == nil || f.IsDir || f.IsSymlink || f.Size <= 0 {
			continue
		}
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(pathpkg.Base(childPath))), ".zip") {
			return true
		}
	}
	return false
}

func (vfs *VirtualFileSystem) markPersistDirtyLocked() {
	vfs.persistVersion++
}

func (vfs *VirtualFileSystem) invalidateRaceCachesForPathLocked(path string) {
	path = cleanVFSPath(path)
	vfs.invalidateRaceCacheLocked(cleanVFSPath(pathpkg.Dir(path)))
	vfs.invalidateRaceCacheLocked(path)
}

func (vfs *VirtualFileSystem) invalidateRaceCacheLocked(dirPath string) {
	dirPath = cleanVFSPath(dirPath)
	if meta := vfs.dirMeta[dirPath]; meta != nil {
		meta.raceCache = nil
		meta.zipRaceCache = nil
	}
}

func (vfs *VirtualFileSystem) clearAllRaceCachesLocked() {
	for _, meta := range vfs.dirMeta {
		if meta == nil {
			continue
		}
		meta.raceCache = nil
		meta.zipRaceCache = nil
	}
}
