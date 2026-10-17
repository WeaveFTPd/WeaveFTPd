package core

import (
	"fmt"
	"io"
	"log"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"weaveftpd/internal/zipscript"
)

func toZipscriptRaceUsers(users []VFSRaceUser) []zipscript.RaceUserStat {
	out := make([]zipscript.RaceUserStat, 0, len(users))
	for _, u := range users {
		out = append(out, zipscript.RaceUserStat{
			Name:    u.Name,
			Group:   u.Group,
			Files:   u.Files,
			Bytes:   u.Bytes,
			Speed:   u.Speed,
			Percent: u.Percent,
		})
	}
	return out
}

func toZipscriptRaceGroups(groups []VFSRaceGroup) []zipscript.RaceGroupStat {
	out := make([]zipscript.RaceGroupStat, 0, len(groups))
	for _, g := range groups {
		out = append(out, zipscript.RaceGroupStat{
			Name:    g.Name,
			Files:   g.Files,
			Bytes:   g.Bytes,
			Speed:   g.Speed,
			Percent: g.Percent,
		})
	}
	return out
}

func HasRaceStats(users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, present, total int) bool {
	return zipscript.HasRaceStats(toZipscriptRaceUsers(users), toZipscriptRaceGroups(groups), totalBytes, present, total)
}

func shouldRenderCWDRaceBanner(cfg *Config, users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, present, total int) bool {
	return cfg != nil && HasRaceStats(users, groups, totalBytes, present, total)
}

func RenderCompactRaceStats(w io.Writer, users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, present, total int) {
	zipscript.RenderCompactRaceStats(w, toZipscriptRaceUsers(users), toZipscriptRaceGroups(groups), totalBytes, present, total)
}

func RenderRaceStats(w io.Writer, users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, present, total int, version string) {
	zipscript.RenderRaceStats(w, toZipscriptRaceUsers(users), toZipscriptRaceGroups(groups), totalBytes, present, total, version)
}

func RenderRaceHeader(w io.Writer, version string) {
	zipscript.RenderRaceHeader(w, version)
}

func RenderFTPReplyBlock(w io.Writer, code int, finalLine string, render func(io.Writer)) {
	zipscript.RenderFTPReplyBlock(w, code, finalLine, render)
}

type zipRuntimeBridge struct {
	MasterBridge
}

func (b zipRuntimeBridge) ListZipDirEntries(dirPath string) []zipscript.ZipEntryInfo {
	entries := b.ListDir(dirPath)
	out := make([]zipscript.ZipEntryInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, zipscript.ZipEntryInfo{
			Name:      e.Name,
			IsDir:     e.IsDir,
			IsSymlink: e.IsSymlink,
			Size:      e.Size,
			XferTime:  e.XferTime,
		})
	}
	return out
}

func zipBridge(bridge MasterBridge) zipscript.ZipRuntimeBridge {
	if bridge == nil {
		return nil
	}
	return zipRuntimeBridge{MasterBridge: bridge}
}

func sfvBridge(bridge MasterBridge) zipscript.SFVRuntimeBridge {
	if bridge == nil {
		return nil
	}
	return bridge
}

type releaseUploadPipelineInput struct {
	UploadDir        string
	MediaInfoDir     string
	FilePath         string
	FileName         string
	Checksum         uint32
	TransferredBytes int64
	FileSize         int64
	SpeedMB          float64
	XferMs           int64
	CompletedAtMs    int64
	ExistingNames    []string
}

type releaseUploadPipelineState struct {
	SFVUpload        bool
	SFVEntries       map[string]uint32
	HadAudioInfo     bool
	HadMediaInfo     bool
	AudioFields      map[string]string
	MediaFields      map[string]string
	RaceUsers        []VFSRaceUser
	RaceGroups       []VFSRaceGroup
	RaceTotalBytes   int64
	RaceTotalFiles   int
	RaceDurationMs   int64
	RaceComplete     bool
	EventData        map[string]string
	ShouldAnnounceNR bool
}

func shouldAnnounceNoRace(cfg *Config, dirPath string, existingNames []string, fileName string) bool {
	if cfg == nil || !cfg.Zipscript.Enabled || !cfg.Zipscript.Race.AnnounceNoRace {
		return false
	}
	if zipscript.IsIgnoredReleaseSubdir(cfg.Zipscript, dirPath) {
		return false
	}
	if zipscript.UsesRace(cfg.Zipscript, dirPath) || zipscript.IsIgnoredType(cfg.Zipscript, fileName) {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(fileName), ".") {
		return false
	}
	for _, name := range existingNames {
		name = strings.TrimSpace(name)
		if name == "" || strings.HasPrefix(name, ".") || zipscript.IsIgnoredType(cfg.Zipscript, name) {
			continue
		}
		return false
	}
	return true
}

func zipDirRaceStats(bridge MasterBridge, dirPath string, entries []MasterFileEntry, expectedTotal int) ([]VFSRaceUser, int64, int) {
	userMap := make(map[string]*VFSRaceUser)
	totalBytes := int64(0)
	total := 0
	for _, e := range entries {
		if e.IsDir || e.IsSymlink || strings.HasPrefix(strings.TrimSpace(e.Name), ".") || !zipscript.IsZipPayloadName(e.Name) {
			continue
		}
		total++
		totalBytes += e.Size
		if e.XferTime <= 0 {
			continue
		}
		owner := e.Owner
		if owner == "" {
			owner = "unknown"
		}
		group := e.Group
		if group == "" {
			group = "NoGroup"
		}
		us := userMap[owner]
		if us == nil {
			us = &VFSRaceUser{Name: owner, Group: group}
			userMap[owner] = us
		}
		us.Files++
		us.Bytes += e.Size
		fileSpeed := float64(e.Size) / (float64(e.XferTime) / 1000.0)
		us.Speed += fileSpeed
		if fileSpeed > us.PeakSpeed {
			us.PeakSpeed = fileSpeed
		}
		if us.SlowSpeed == 0 || fileSpeed < us.SlowSpeed {
			us.SlowSpeed = fileSpeed
		}
		us.DurationMs += e.XferTime
	}
	users := make([]VFSRaceUser, 0, len(userMap))
	for _, us := range userMap {
		percentBase := total
		if expectedTotal > 0 {
			percentBase = expectedTotal
		}
		if percentBase > 0 {
			us.Percent = (us.Files * 100) / percentBase
		}
		if us.DurationMs > 0 {
			us.Speed = float64(us.Bytes) / (float64(us.DurationMs) / 1000.0)
		}
		users = append(users, *us)
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].Files != users[j].Files {
			return users[i].Files > users[j].Files
		}
		if users[i].Bytes != users[j].Bytes {
			return users[i].Bytes > users[j].Bytes
		}
		return strings.ToLower(users[i].Name) < strings.ToLower(users[j].Name)
	})
	return users, totalBytes, total
}

func raceGroupsFromUsers(users []VFSRaceUser, totalFiles int) []VFSRaceGroup {
	groupMap := make(map[string]*VFSRaceGroup)
	for _, u := range users {
		group := strings.TrimSpace(u.Group)
		if group == "" {
			group = "NoGroup"
		}
		g := groupMap[group]
		if g == nil {
			g = &VFSRaceGroup{Name: group}
			groupMap[group] = g
		}
		g.Files += u.Files
		g.Bytes += u.Bytes
		g.Speed += u.Speed
	}
	groups := make([]VFSRaceGroup, 0, len(groupMap))
	for _, g := range groupMap {
		if totalFiles > 0 {
			g.Percent = (g.Files * 100) / totalFiles
		}
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Bytes != groups[j].Bytes {
			return groups[i].Bytes > groups[j].Bytes
		}
		if groups[i].Files != groups[j].Files {
			return groups[i].Files > groups[j].Files
		}
		return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name)
	})
	return groups
}

func releaseStatusForDir(bridge MasterBridge, dirPath string) (ReleaseStatus, bool) {
	if bridge == nil {
		return ReleaseStatus{}, false
	}
	return bridge.GetReleaseStatus(dirPath)
}

func releaseStatusComplete(status ReleaseStatus) bool {
	return raceCountsComplete(status.Present, status.Total)
}

// raceCountsComplete reports whether present has reached the expected total.
// An unknown total (<= 0) is never complete: for zip races this means the
// file_id.diz-derived part count hasn't been read yet (it lives inside
// whichever payload .zip carries it, which may not be the first one to
// land), not that there's no count to track, so a low presentCount must not
// be reported complete just because the total isn't known yet. This is the
// single source of truth for the "is this release/file done" boolean that
// used to be reimplemented ad hoc at each call site, with the zip path
// briefly disagreeing with the rest (see vfs.go's checksum-verification
// consolidation for the same pattern applied to CRC comparisons).
func raceCountsComplete(present, total int) bool {
	return total > 0 && present >= total
}

func incompleteMarkerName(pattern, relname string) string {
	return zipscript.StatusMarkerName(pattern, relname)
}

func incompleteMarkerName2(pattern, relname, child string) string {
	return zipscript.StatusMarkerNameForChild(pattern, relname, child)
}

func markerLinkTarget(dirPath, relName string) string {
	return path.Clean(path.Join("/", strings.TrimSpace(dirPath), strings.TrimSpace(relName)))
}

func isIncompleteMarkerName(pattern, name string) bool {
	return zipscript.IsIncompleteMarkerName(pattern, name)
}

func resolveKnownMarkerTarget(bridge MasterBridge, cfg *Config, parent, name string) string {
	if bridge == nil || cfg == nil {
		return ""
	}
	patterns := []string{
		activeIncompleteIndicator(cfg),
		zipscript.NoSFVIndicator(cfg.Zipscript),
		zipscript.NFOIndicator(cfg.Zipscript),
		zipscript.CDIndicator(cfg.Zipscript),
	}
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		if !isIncompleteMarkerName(pattern, name) {
			continue
		}
		markerPath := path.Clean(path.Join("/", strings.TrimSpace(parent), strings.TrimSpace(name)))
		if entry, found := bridge.GetPathEntry(markerPath); found && entry.IsSymlink && strings.TrimSpace(entry.LinkTarget) != "" {
			target := path.Clean("/" + strings.TrimSpace(entry.LinkTarget))
			if bridge.FileExists(target) {
				return target
			}
			return target
		}
	}
	return ""
}

func hasNFOEntry(entries []MasterFileEntry) bool {
	for _, entry := range entries {
		if entry.IsDir {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name), ".nfo") {
			return true
		}
	}
	return false
}

func hasSFVEntry(entries []MasterFileEntry) bool {
	for _, entry := range entries {
		if entry.IsDir {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name), ".sfv") {
			return true
		}
	}
	return false
}

func syncMasterSFVMissingMarkers(cfg *Config, bridge MasterBridge, dirPath string) {
	if cfg == nil || bridge == nil || !zipscript.ShowMissingFilesForDir(cfg.Zipscript, dirPath) {
		return
	}
	status, ok := releaseStatusForDir(bridge, dirPath)
	if !ok || status.Kind != "sfv" || len(status.ExpectedFiles) == 0 {
		return
	}

	missingSet := make(map[string]bool, len(status.MissingFiles))
	for _, name := range status.MissingFiles {
		missingSet[raceCRCKey(name)] = true
	}

	for _, fileName := range status.ExpectedFiles {
		missingPath := path.Join(dirPath, fileName+"-MISSING")
		if missingSet[raceCRCKey(fileName)] {
			if bridge.GetFileSize(missingPath) < 0 {
				_ = bridge.WriteFile(missingPath, []byte{})
			}
			continue
		}
		if bridge.GetFileSize(missingPath) >= 0 {
			_ = bridge.DeleteFile(missingPath)
		}
	}
}

func clearMasterSFVMissingMarker(bridge MasterBridge, dirPath, fileName string) {
	if bridge == nil {
		return
	}
	missingPath := path.Join(dirPath, fileName+"-MISSING")
	if bridge.GetFileSize(missingPath) >= 0 {
		_ = bridge.DeleteFile(missingPath)
	}
}

func createMasterSFVMissingMarker(cfg *Config, bridge MasterBridge, dirPath, fileName string) {
	if cfg == nil || bridge == nil || !zipscript.ShowMissingFilesForDir(cfg.Zipscript, dirPath) {
		return
	}
	missingPath := path.Join(dirPath, fileName+"-MISSING")
	if bridge.GetFileSize(missingPath) < 0 {
		_ = bridge.WriteFile(missingPath, []byte{})
	}
}

func isZeroByteCriticalFile(fileName string) bool {
	l := strings.ToLower(strings.TrimSpace(fileName))
	return strings.HasSuffix(l, ".sfv") || strings.HasSuffix(l, ".nfo") || strings.HasSuffix(l, ".diz")
}

// criticalUploadHasRealContent reports whether a critical metadata file the master
// measured as 0 bytes actually has usable content on the slave. The passthrough
// transfer size can momentarily read 0 for a file that is complete on disk; if we
// delete it then, a good .sfv is dropped and the release is never SFV-checked or
// announced complete. For an .sfv we ask the slave to parse it (authoritative,
// reads the real file) -- if it yields entries, the file is real and must be kept.
func firstSFVNameInDir(bridge MasterBridge, dirPath string) string {
	if bridge == nil {
		return ""
	}
	for _, e := range bridge.ListDir(dirPath) {
		if e.IsDir || e.IsSymlink {
			continue
		}
		if strings.EqualFold(path.Ext(e.Name), ".sfv") {
			return e.Name
		}
	}
	return ""
}

func criticalUploadHasRealContent(bridge MasterBridge, filePath, fileName string) bool {
	if bridge == nil {
		return false
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(fileName)), ".sfv") {
		if info, err := bridge.GetSFVInfo(filePath); err == nil && len(info.Entries) > 0 {
			return true
		}
	}
	return false
}

func ensureSFVDataAvailable(cfg *Config, bridge MasterBridge, dirPath string) map[string]uint32 {
	if bridge == nil {
		return nil
	}
	if sfvEntries := bridge.GetSFVData(dirPath); sfvEntries != nil {
		return sfvEntries
	}
	sfvName := firstSFVNameInDir(bridge, dirPath)
	if sfvName == "" {
		return nil
	}
	info, err := bridge.GetSFVInfo(path.Join(dirPath, sfvName))
	if err != nil || len(info.Entries) == 0 {
		return nil
	}
	log.Printf("[MASTER-ZS] Recovered uncached SFV %s: %d entries", sfvName, len(info.Entries))
	bridge.CacheSFV(dirPath, sfvName, info)
	verifyExistingPayloadsAfterSFVUpload(cfg, bridge, dirPath)
	return bridge.GetSFVData(dirPath)
}

// maybeGenerateReleaseM3U creates an .m3u playlist from the SFV for a completed
// MP3/FLAC release (pzs-ng create_m3u behaviour). weaveftpd does not otherwise produce
// an m3u, so without this an outbound race / link script can complete before a
// racer uploads one. No-op when disabled, the section is not MP3/FLAC, there is no
// SFV, or the release already has an .m3u.
func maybeGenerateReleaseM3U(s *Session, bridge MasterBridge, dirPath string) {
	if s == nil || s.Config == nil || bridge == nil {
		return
	}
	cfg := s.Config.Zipscript
	if !zipscript.CreateM3UEnabled(cfg, dirPath) {
		return
	}

	entries := bridge.ListDir(dirPath)
	names := make([]string, 0, len(entries))
	sfvName := ""
	for _, e := range entries {
		if e.IsDir || e.IsSymlink {
			continue
		}
		names = append(names, e.Name)
		if sfvName == "" && strings.EqualFold(path.Ext(e.Name), ".sfv") {
			sfvName = e.Name
		}
	}
	if sfvName == "" {
		return
	}

	m3uName, body, ok := zipscript.BuildReleaseM3U(cfg, sfvName, names, bridge.GetSFVData(dirPath))
	if !ok {
		return
	}
	m3uPath := path.Join(dirPath, m3uName)
	if err := bridge.WriteFile(m3uPath, body); err != nil {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] m3u generation failed for %s: %v", dirPath, err)
		}
		return
	}
	if s.Config.Debug {
		log.Printf("[MASTER-ZS] generated %s for %s", m3uName, dirPath)
	}
}

func handleMasterUploadSFVStatusAndCleanup(s *Session, bridge MasterBridge, uploadDir, filePath, fileName string, checksum uint32, fileSize int64) bool {
	if s == nil || s.Config == nil || bridge == nil || strings.HasSuffix(strings.ToLower(fileName), ".sfv") {
		return false
	}

	sfvEntries := ensureSFVDataAvailable(s.Config, bridge, uploadDir)
	expectedCRC, exists := zipscript.CachedExpectedCRC(sfvEntries, fileName)
	if !exists {
		zipscript.WriteUploadNoSFVEntryStatus(s.Conn, sfvEntries, fileName)
		return false
	}

	zipscript.WriteUploadSFVStatus(s.Conn, checksum, expectedCRC, true, fileSize)
	if checksum == expectedCRC && checksum != 0 {
		return false
	}

	if checksum == 0 || expectedCRC == 0 || !zipscript.ShouldDeleteBadCRCForDir(s.Config.Zipscript, uploadDir) {
		return false
	}

	if err := bridge.DeleteFile(filePath); err != nil && s.Config.Debug && !zipscript.IsNotFoundDeleteError(err) {
		log.Printf("[MASTER-ZS] CRC mismatch delete failed for %s: %v", filePath, err)
	}
	_ = bridge.MarkFileMissing(filePath)
	createMasterSFVMissingMarker(s.Config, bridge, uploadDir, fileName)
	log.Printf("[MASTER-ZS] CRC mismatch for %s: got %08X, expected %08X - deleted before final reply",
		fileName, checksum, expectedCRC)
	writeChecksumMismatchDeleteResponse(s.Conn, checksum, expectedCRC)
	return true
}

func handleMasterUploadZipIntegrityAndCleanup(s *Session, bridge MasterBridge, uploadDir, filePath, fileName string) bool {
	if s == nil || s.Config == nil || bridge == nil {
		return false
	}
	badZip, err := zipscript.CheckUploadedZipIntegrity(zipBridge(bridge), s.Config.Zipscript, uploadDir, filePath, fileName)
	if err != nil {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] zip integrity check skipped for %s: %v", filePath, err)
		}
		return false
	}
	if !badZip {
		return false
	}
	writeZipIntegrityFailureDeleteResponse(s.Conn)
	return true
}

func handleMasterDownloadSFVChecksum(s *Session, bridge MasterBridge, filePath string, transferChecksum uint32) {
	if s == nil || s.Config == nil || bridge == nil || transferChecksum == 0 {
		return
	}
	dirPath := path.Dir(filePath)
	fileName := path.Base(filePath)
	expectedCRC, ok := zipscript.CachedExpectedCRC(bridge.GetSFVData(dirPath), fileName)
	if !ok || expectedCRC == 0 {
		return
	}
	_ = bridge.SyncPresentFile(filePath, transferChecksum)
	if transferChecksum == expectedCRC {
		clearMasterSFVMissingMarker(bridge, dirPath, fileName)
		bridge.SyncStatusMarkersForPath(filePath, false)
		return
	}
	createMasterSFVMissingMarker(s.Config, bridge, dirPath, fileName)
	bridge.SyncStatusMarkersForPath(filePath, false)
	fmt.Fprintf(s.Conn, "226- WARNING: checksum from transfer didn't match checksum in .sfv\r\n")
}

func zipRaceCountsFromStatus(status ReleaseStatus) (present int, total int) {
	if status.Kind != "zip" {
		return 0, 0
	}
	return status.Present, status.Total
}

func sfvRaceCountsFromStatus(status ReleaseStatus) (present int, total int) {
	if status.Kind != "sfv" {
		return 0, 0
	}
	return status.Present, status.Total
}

func missingFilesSummary(status ReleaseStatus) string {
	if len(status.MissingFiles) == 0 {
		return ""
	}
	names := append([]string(nil), status.MissingFiles...)
	sort.Strings(names)
	return fmt.Sprintf("%d missing: %s", len(names), strings.Join(names, ", "))
}

func raceStatsForDir(bridge MasterBridge, cfg *Config, dirPath string) (users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, present int, total int) {
	if bridge == nil || cfg == nil {
		return nil, nil, 0, 0, 0
	}
	if useZipRaceMode(bridge, cfg, dirPath, "") {
		entries := bridge.ListDir(dirPath)
		status, ok := releaseStatusForDir(bridge, dirPath)
		expected := 0
		if ok && status.Kind == "zip" {
			present, total = zipRaceCountsFromStatus(status)
			expected = total
		} else {
			expected = zipscript.ZipExpectedPartsFromDIZ(zipBridge(bridge), dirPath, false)
			present = zipscript.ZipDirPayloadCount(zipBridge(bridge).ListZipDirEntries(dirPath))
			if expected > 0 {
				total = expected
			} else {
				total = present
			}
		}
		users, totalBytes, _ = zipDirRaceStats(bridge, dirPath, entries, expected)
		groups = raceGroupsFromUsers(users, total)
		return users, groups, totalBytes, present, total
	}
	// Listing status must use the snapshot path. Fresh slave requests are kept
	// for upload completion, where the final race result needs current data.
	return bridge.GetVFSRaceStats(dirPath)
}

func populateUploadRaceData(bridge MasterBridge, cfg *Config, dirPath, fileName string, fileSize int64, data map[string]string) ([]VFSRaceUser, []VFSRaceGroup, int64, int, int64, bool) {
	type freshRaceStatsBridge interface {
		GetVFSRaceStatsFresh(dirPath string) (users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, present int, total int)
	}

	sfvEntries := bridge.GetSFVData(dirPath)
	usesZip := useZipRaceMode(bridge, cfg, dirPath, fileName)
	isTrackedPayload := isTrackedRacePayload(bridge, cfg, dirPath, fileName)
	if !isTrackedPayload && !usesZip {
		return nil, nil, 0, 0, 0, false
	}
	if isTrackedPayload {
		data["file_mbytes"] = mbString(fileSize)
	}
	if usesZip {
		entries := bridge.ListDir(dirPath)
		status, ok := releaseStatusForDir(bridge, dirPath)
		expected := 0
		presentCount := 0
		if ok && status.Kind == "zip" {
			presentCount, expected = zipRaceCountsFromStatus(status)
		} else {
			expected = zipscript.ZipExpectedPartsFromDIZ(zipBridge(bridge), dirPath, true)
			presentCount = zipscript.ZipDirPayloadCount(zipBridge(bridge).ListZipDirEntries(dirPath))
		}
		users, totalBytes, _ := zipDirRaceStats(bridge, dirPath, entries, expected)
		zipscript.CacheZipReleaseProgress(zipBridge(bridge), dirPath, presentCount, expected)
		if presentCount > 0 {
			raceDurationMs := bridge.GetRaceWallClockMilliseconds(dirPath)
			// pzs-ng: live avg speed is the mean of racer file speeds.
			avgSpeedMB := aggregateRaceSpeedMB(users)
			if avgSpeedMB <= 0 {
				avgSpeedMB = currentRaceSpeedMB(dirPath, totalBytes, bridge)
			}
			if avgSpeedMB <= 0 {
				avgSpeedMB = raceSpeedMBForDuration(totalBytes, raceDurationMs)
			}
			totalFiles := presentCount
			if expected > 0 {
				totalFiles = expected
			}
			groups := raceGroupsFromUsers(users, totalFiles)
			data["relname"] = zipscript.ReleaseDisplayName(dirPath)
			if expected > 0 {
				data["t_files"] = fmt.Sprintf("%d", expected)
				data["t_present"] = fmt.Sprintf("%d", presentCount)
				data["t_filesleft"] = fmt.Sprintf("%d", maxInt(0, expected-presentCount))
			} else {
				delete(data, "t_files")
				delete(data, "t_present")
				delete(data, "t_filesleft")
			}
			data["t_totalmb"] = fmt.Sprintf("%.1f", float64(totalBytes)/1024.0/1024.0)
			data["t_avgspeed"] = fmt.Sprintf("%.2fMB/s", avgSpeedMB)
			if expected > 0 && expected > presentCount {
				data["t_timeleft"] = estimateRaceTimeLeftWithSpeed(totalBytes, presentCount, expected, avgSpeedMB)
			} else if expected > 0 {
				data["t_timeleft"] = "0s"
			} else {
				delete(data, "t_timeleft")
			}
			data["t_mbytes"] = fmt.Sprintf("%.0fMB", float64(totalBytes)/1024.0/1024.0)
			if len(users) > 0 {
				leader := users[0]
				data["leader_name"] = leader.Name
				data["leader_group"] = leader.Group
				data["leader_files"] = fmt.Sprintf("%d", leader.Files)
				data["leader_mb"] = fmt.Sprintf("%.1f", float64(leader.Bytes)/1024.0/1024.0)
				data["leader_pct"] = fmt.Sprintf("%d", leader.Percent)
				data["leader_speed"] = fmt.Sprintf("%.2fMB/s", leader.Speed/1024.0/1024.0)
			}
			return users, groups, totalBytes, totalFiles, raceDurationMs, raceCountsComplete(presentCount, expected)
		}
		return nil, nil, 0, 0, 0, false
	}
	if sfvEntries != nil {
		var users []VFSRaceUser
		var groups []VFSRaceGroup
		var totalBytes int64
		var present, total int
		raceDurationMs := int64(0)
		if freshBridge, ok := bridge.(freshRaceStatsBridge); ok {
			users, groups, totalBytes, present, total = freshBridge.GetVFSRaceStatsFresh(dirPath)
		} else {
			users, groups, totalBytes, present, total = bridge.GetVFSRaceStats(dirPath)
		}
		raceDurationMs = bridge.GetRaceWallClockMilliseconds(dirPath)
		if total > 0 {
			// pzs-ng: live avg speed is the mean of racer file speeds.
			avgSpeedMB := aggregateRaceSpeedMB(users)
			if avgSpeedMB <= 0 {
				avgSpeedMB = currentRaceSpeedMB(dirPath, totalBytes, bridge)
			}
			if avgSpeedMB <= 0 {
				avgSpeedMB = raceSpeedMBForDuration(totalBytes, raceDurationMs)
			}
			data["relname"] = zipscript.ReleaseDisplayName(dirPath)
			data["t_files"] = fmt.Sprintf("%d", total)
			data["t_present"] = fmt.Sprintf("%d", present)
			data["t_filesleft"] = fmt.Sprintf("%d", maxInt(0, total-present))
			data["t_totalmb"] = fmt.Sprintf("%.1f", float64(totalBytes)/1024.0/1024.0)
			data["t_avgspeed"] = fmt.Sprintf("%.2fMB/s", avgSpeedMB)
			data["t_timeleft"] = estimateRaceTimeLeftWithSpeed(totalBytes, present, total, avgSpeedMB)
			estBytes := fileSize * int64(total)
			data["t_mbytes"] = fmt.Sprintf("%.0fMB", float64(estBytes)/1024.0/1024.0)
			if len(users) > 0 {
				leader := users[0]
				data["leader_name"] = leader.Name
				data["leader_group"] = leader.Group
				data["leader_files"] = fmt.Sprintf("%d", leader.Files)
				data["leader_mb"] = fmt.Sprintf("%.1f", float64(leader.Bytes)/1024.0/1024.0)
				data["leader_pct"] = fmt.Sprintf("%d", leader.Percent)
				data["leader_speed"] = fmt.Sprintf("%.2fMB/s", leader.Speed/1024.0/1024.0)
			}
			return users, groups, totalBytes, total, raceDurationMs, raceCountsComplete(present, total)
		}
	}
	return nil, nil, 0, 0, 0, false
}

func progressBar(present, total, width int) string {
	return zipscript.ProgressBar(present, total, width)
}

func currentRaceSpeedMB(dirPath string, totalBytes int64, bridge MasterBridge) float64 {
	if bridge == nil || totalBytes <= 0 {
		return 0
	}
	ms := bridge.GetRaceWallClockMilliseconds(dirPath)
	if ms <= 0 {
		return 0
	}
	return (float64(totalBytes) / 1024.0 / 1024.0) / (float64(ms) / 1000.0)
}

// aggregateRaceSpeedMB returns the combined race throughput: the sum of every
// racer's combined per-user speed. With parallel slots this is the high
// headline number sites expect on the COMPLETE line.
func aggregateRaceSpeedMB(users []VFSRaceUser) float64 {
	total := 0.0
	for _, u := range users {
		if u.Speed > 0 {
			total += u.Speed
		}
	}
	return total / 1024.0 / 1024.0
}

func maxUserRaceDurationMs(users []VFSRaceUser) int64 {
	var maxMs int64
	for _, u := range users {
		if u.DurationMs > maxMs {
			maxMs = u.DurationMs
		}
	}
	return maxMs
}

func raceSpeedMBForDuration(totalBytes int64, durationMs int64) float64 {
	if totalBytes <= 0 || durationMs <= 0 {
		return 0
	}
	return (float64(totalBytes) / 1024.0 / 1024.0) / (float64(durationMs) / 1000.0)
}

func estimateRaceTimeLeftWithSpeed(totalBytes int64, present, total int, speedMB float64) string {
	if totalBytes <= 0 || present <= 0 || total <= present {
		return "0s"
	}
	if speedMB <= 0 {
		return "N/A"
	}
	avgBytesPerFile := float64(totalBytes) / float64(present)
	bytesLeft := avgBytesPerFile * float64(total-present)
	seconds := int((bytesLeft / 1024.0 / 1024.0) / speedMB)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}

func estimateRaceTimeLeft(dirPath string, totalBytes int64, present, total int, bridge MasterBridge) string {
	if totalBytes <= 0 || present <= 0 || total <= present {
		return "0s"
	}
	speed := currentRaceSpeedMB(dirPath, totalBytes, bridge)
	if speed <= 0 {
		return "N/A"
	}
	avgBytesPerFile := float64(totalBytes) / float64(present)
	bytesLeft := avgBytesPerFile * float64(total-present)
	seconds := int((bytesLeft / 1024.0 / 1024.0) / speed)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}

func estimateZipTimeLeft(dirPath string, totalBytes int64, present, total int, bridge MasterBridge) string {
	if totalBytes <= 0 || present <= 0 || total <= present {
		return "0s"
	}
	speed := currentRaceSpeedMB(dirPath, totalBytes, bridge)
	if speed <= 0 {
		return "N/A"
	}
	avgBytesPerFile := float64(totalBytes) / float64(present)
	bytesLeft := avgBytesPerFile * float64(total-present)
	seconds := int((bytesLeft / 1024.0 / 1024.0) / speed)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}

func dirRaceProgress(bridge MasterBridge, cfg *Config, dirPath string) (totalBytes int64, present int, total int) {
	if bridge == nil || cfg == nil {
		return 0, 0, 0
	}
	if !zipscript.RaceStatusEligibleDir(dirPath) || !zipscript.UsesRaceEntry(cfg.Zipscript, dirPath) {
		return 0, 0, 0
	}
	_, _, totalBytes, present, total = raceStatsForDir(bridge, cfg, dirPath)
	return totalBytes, present, total
}

func dirRaceStatusName(bridge MasterBridge, cfg *Config, dirPath, siteName string) string {
	if !zipscript.RaceStatusEligibleDir(dirPath) {
		return ""
	}
	var statusEntries []string
	totalBytes, present, total := dirRaceProgress(bridge, cfg, dirPath)
	extra := listStatusAudioExtra(bridge, cfg, dirPath)
	if total > 0 {
		totalMB := float64(totalBytes) / (1024 * 1024)
		if raceCountsComplete(present, total) {
			if extra != "" {
				statusEntries = append(statusEntries, fmt.Sprintf("[%s] - ( %.0fM %dF - COMPLETE - %s ) - [%s]", siteName, totalMB, total, extra, siteName))
				extra = ""
			} else {
				statusEntries = append(statusEntries, fmt.Sprintf("[%s] - ( %.0fM %dF - COMPLETE ) - [%s]", siteName, totalMB, total, siteName))
			}
		} else {
			pct := (present * 100) / total
			if extra != "" {
				statusEntries = append(statusEntries, fmt.Sprintf("[%s] - ( %s %3d%% COMPLETE - %s ) - [%s]", siteName, zipscript.ProgressBar(present, total, 20), pct, extra, siteName))
				extra = ""
			} else {
				statusEntries = append(statusEntries, fmt.Sprintf("[%s] - ( %s %3d%% COMPLETE ) - [%s]", siteName, zipscript.ProgressBar(present, total, 20), pct, siteName))
			}
		}
	}
	if extra != "" {
		statusEntries = append(statusEntries, extra)
	}
	switch len(statusEntries) {
	case 0:
		return ""
	case 1:
		if total > 0 {
			return statusEntries[0]
		}
		return "[" + statusEntries[0] + "]"
	default:
		return strings.Join(statusEntries, " | ")
	}
}

func listStatusAudioExtra(bridge MasterBridge, cfg *Config, dirPath string) string {
	if bridge == nil || cfg == nil {
		return ""
	}
	if !cfg.Zipscript.Enabled || !cfg.Zipscript.Audio.Enabled {
		return ""
	}
	section, _ := zipscript.SectionInfoFromPath(dirPath)
	switch strings.ToUpper(strings.TrimSpace(section)) {
	case "MP3", "FLAC":
	default:
		return ""
	}
	info := bridge.GetDirMediaInfo(dirPath)
	if !zipscript.AudioInfoLooksUsable(info) {
		return ""
	}
	genre := zipscript.FirstNonEmptyMap(info, "genre", "g_genre")
	year := zipscript.NormalizeAudioYearForStatus(zipscript.FirstNonEmptyMap(info, "year", "g_recordeddate", "g_recorded_date", "g_originalreleaseddate", "g_original_released_date"))
	switch {
	case genre != "" && year != "":
		return genre + " " + year
	case genre != "":
		return genre
	default:
		return year
	}
}

func isTrackedRacePayload(bridge MasterBridge, cfg *Config, dirPath, fileName string) bool {
	if bridge == nil || cfg == nil {
		return false
	}
	sfvEntries := bridge.GetSFVData(dirPath)
	isTrackedPayload := zipscript.IsRacePayloadFileForDir(cfg.Zipscript, dirPath, fileName)
	if sfvEntries != nil {
		_, isTrackedPayload = sfvEntries[strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(fileName, "\\", "/"))))]
		if !isTrackedPayload {
			isTrackedPayload = zipscript.IsRacePayloadFileForDir(cfg.Zipscript, dirPath, fileName)
		}
	}
	return isTrackedPayload
}

func firstTrackedRaceFileName(bridge MasterBridge, dirPath string) string {
	sfvEntries := bridge.GetSFVData(dirPath)
	for name := range sfvEntries {
		if strings.TrimSpace(name) != "" {
			return name
		}
	}
	return ""
}

func enrichUploadRaceUserData(data map[string]string, users []VFSRaceUser, username string) {
	if data == nil || len(users) == 0 || strings.TrimSpace(username) == "" {
		return
	}
	for _, u := range users {
		if !strings.EqualFold(strings.TrimSpace(u.Name), strings.TrimSpace(username)) {
			continue
		}
		data["u_race_speed"] = fmt.Sprintf("%.2fMB/s", userDisplaySpeed(u)/1024.0/1024.0)
		data["u_race_files"] = fmt.Sprintf("%d", u.Files)
		data["u_race_mb"] = fmt.Sprintf("%.1f", float64(u.Bytes)/1024.0/1024.0)
		data["u_race_pct"] = fmt.Sprintf("%d", u.Percent)
		if strings.TrimSpace(data["u_group"]) == "" && strings.TrimSpace(u.Group) != "" {
			data["u_group"] = u.Group
		}
		return
	}
}

func shouldEmitZipRaceEnd(cfg *Config, dirPath, fileName string) bool {
	if cfg == nil || !zipscript.UsesZip(cfg.Zipscript, dirPath) {
		return false
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(fileName)), ".zip")
}

func useZipRaceMode(bridge MasterBridge, cfg *Config, dirPath, fileName string) bool {
	if cfg == nil || !zipscript.UsesZip(cfg.Zipscript, dirPath) {
		return false
	}
	if !zipscript.UsesSFV(cfg.Zipscript, dirPath) {
		return true
	}
	if zipscript.IsZipPayloadName(fileName) || zipscript.IsZipManifestName(fileName) {
		return true
	}
	if bridge == nil {
		return false
	}
	if bridge.GetSFVData(dirPath) != nil {
		return false
	}
	for _, entry := range bridge.ListDir(dirPath) {
		if entry.IsDir || entry.IsSymlink {
			continue
		}
		if zipscript.IsZipPayloadName(entry.Name) || zipscript.IsZipManifestName(entry.Name) {
			return true
		}
	}
	return false
}

func emitPrefixedCommentLines(conn net.Conn, prefix string, lines []string) {
	if conn == nil {
		return
	}
	for _, line := range lines {
		line = strings.TrimRight(strings.ReplaceAll(line, "\r\n", "\n"), "\n")
		if line == "" {
			continue
		}
		for _, part := range strings.Split(line, "\n") {
			fmt.Fprintf(conn, "%s-%s\r\n", prefix, part)
		}
	}
}

func emitCWDZipDIZInfo(s *Session, bridge MasterBridge, dirPath string) {
	if s == nil || bridge == nil || !zipscript.ShowZipDIZOnCWDForDir(s.Config.Zipscript, dirPath) {
		return
	}
	content, err := bridge.ReadFile(path.Join(dirPath, "file_id.diz"))
	if err != nil || len(content) == 0 {
		return
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	emitPrefixedCommentLines(s.Conn, "250", lines)
}

func emitCWDAudioInfo(s *Session, bridge MasterBridge, dirPath string) {
	if s == nil || bridge == nil {
		return
	}
	fields := bridge.GetDirMediaInfo(dirPath)
	if !zipscript.AudioInfoLooksUsable(fields) {
		if refreshed, ok := maybeBootstrapCWDAudioInfo(s, bridge, dirPath); ok {
			fields = refreshed
		}
	}
	if !zipscript.ShowAudioInfoOnCWDForDir(s.Config.Zipscript, dirPath, fields) {
		return
	}
	emitPrefixedCommentLines(s.Conn, "250", zipscript.BuildAudioInfoBox(dirPath, fields, s.Config.Version))
}

func maybeBootstrapCWDAudioInfo(s *Session, bridge MasterBridge, dirPath string) (map[string]string, bool) {
	if s == nil || bridge == nil || s.Config == nil {
		return nil, false
	}
	section, _ := zipscript.SectionInfoFromPath(dirPath)
	section = strings.ToUpper(strings.TrimSpace(section))
	audioEnabled := false
	switch section {
	case "MP3":
		audioEnabled = s.Config.Zipscript.Enabled && s.Config.Zipscript.Audio.Enabled &&
			s.Config.Zipscript.Audio.CWDMP3Info != nil && *s.Config.Zipscript.Audio.CWDMP3Info
	case "FLAC":
		audioEnabled = s.Config.Zipscript.Enabled && s.Config.Zipscript.Audio.Enabled &&
			s.Config.Zipscript.Audio.CWDFLACInfo != nil && *s.Config.Zipscript.Audio.CWDFLACInfo
	}
	if !audioEnabled {
		return nil, false
	}
	candidate, fields, ok := findFirstUsableAudioInfo(bridge, s.Config, dirPath)
	if !ok {
		return nil, false
	}
	previousFields := cloneStringMap(bridge.GetDirMediaInfo(dirPath))
	bridge.CacheMediaInfo(dirPath, fields)
	if err := refreshAudioSortLinks(bridge, s.Config.Zipscript, dirPath, previousFields, fields); err != nil && s.Config.Debug {
		log.Printf("[MASTER-ZS] cwd audio bootstrap sort link failed for %s: %v", dirPath, err)
	}
	if s.Config.Debug {
		log.Printf("[MASTER-ZS] cwd audio bootstrap refreshed %s from %s", dirPath, candidate)
	}
	return fields, true
}

func emitSTORAudioInfo(s *Session, dirPath string, fields map[string]string) {
	if s == nil || !zipscript.ShowAudioInfoOnSTORForDir(s.Config.Zipscript, dirPath, fields) {
		return
	}
	emitPrefixedCommentLines(s.Conn, "226", zipscript.BuildAudioInfoLines(dirPath, fields, true))
}

func firstNonEmptyMap(values map[string]string, keys ...string) string {
	return zipscript.FirstNonEmptyMap(values, keys...)
}

func ensureAudioSortLinks(bridge MasterBridge, links []zipscript.AudioSortLink) error {
	for _, link := range links {
		if err := ensureDirPath(bridge, link.DirPath); err != nil {
			return err
		}
		if err := bridge.Symlink(link.LinkPath, link.Target); err != nil {
			return err
		}
	}
	return nil
}

func ensureDirPathOwned(bridge MasterBridge, dirPath, owner, group string) error {
	dirPath = path.Clean("/" + strings.TrimSpace(dirPath))
	if dirPath == "/" || dirPath == "." {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(dirPath, "/"), "/")
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = path.Join(current, "/"+part)
		if !bridge.FileExists(current) {
			if err := bridge.MakeDir(current, owner, group); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureDirPath(bridge MasterBridge, dirPath string) error {
	return ensureDirPathOwned(bridge, dirPath, "WeaveFTPd", "WeaveFTPd")
}

func runReleaseUploadPipeline(s *Session, bridge MasterBridge, in releaseUploadPipelineInput) {
	if s == nil || s.Config == nil || bridge == nil {
		return
	}
	if !finalizeReleaseUpload(s, bridge, in) {
		return
	}

	state := buildReleaseUploadPipelineState(s, bridge, in)
	emitReleaseUploadMetadata(s, bridge, in, state)
	emitReleaseUploadEventAndRace(s, bridge, in, state)
}

func finalizeReleaseUpload(s *Session, bridge MasterBridge, in releaseUploadPipelineInput) bool {
	if s == nil || s.Config == nil || bridge == nil {
		return false
	}

	if in.Checksum > 0 && zipscript.ShouldDeleteBadCRCForDir(s.Config.Zipscript, in.UploadDir) && !strings.HasSuffix(strings.ToLower(in.FileName), ".sfv") {
		sfvEntries := bridge.GetSFVData(in.UploadDir)
		if sfvEntries != nil {
			if expectedCRC, exists := zipscript.CachedExpectedCRC(sfvEntries, in.FileName); exists {
				if expectedCRC != in.Checksum {
					bridge.DeleteFile(in.FilePath)
					_ = bridge.MarkFileMissing(in.FilePath)
					createMasterSFVMissingMarker(s.Config, bridge, in.UploadDir, in.FileName)
					log.Printf("[MASTER-ZS] CRC mismatch for %s: got %08X, expected %08X - deleted",
						in.FileName, in.Checksum, expectedCRC)
					return false
				}
				clearMasterSFVMissingMarker(bridge, in.UploadDir, in.FileName)
			}
		}
	}

	if s.User != nil && in.TransferredBytes > 0 {
		isSpeedtest := isSpeedtestPath(in.FilePath)
		s.User.UpdateStatsWithCredits(in.TransferredBytes, true, !isSpeedtest)
	}

	return true
}

func buildReleaseUploadPipelineState(s *Session, bridge MasterBridge, in releaseUploadPipelineInput) releaseUploadPipelineState {
	state := releaseUploadPipelineState{
		SFVUpload: strings.HasSuffix(strings.ToLower(in.FileName), ".sfv"),
		EventData: map[string]string{},
	}

	if state.SFVUpload {
		if sfvInfo, err := bridge.GetSFVInfo(in.FilePath); err == nil {
			log.Printf("[MASTER-ZS] Parsed SFV %s: %d entries", in.FileName, len(sfvInfo.Entries))
			bridge.CacheSFV(in.UploadDir, in.FileName, sfvInfo)
			verifyExistingPayloadsAfterSFVUpload(s.Config, bridge, in.UploadDir)
		}
	}
	state.SFVEntries = bridge.GetSFVData(in.UploadDir)
	if state.SFVEntries == nil && !state.SFVUpload {
		// Self-heal: a .sfv is present on the slave but was never cached (or the
		// cache was invalidated by weak VFS metadata). Parse it now from the slave
		// so the release is tracked, CRC-checked, and eligible for COMPLETE.
		state.SFVEntries = ensureSFVDataAvailable(s.Config, bridge, in.UploadDir)
	}
	if state.SFVEntries != nil {
		syncMasterSFVMissingMarkers(s.Config, bridge, in.UploadDir)
		bridge.SyncStatusMarkersForPath(in.UploadDir, true)
	}

	if err := zipscript.RefreshZipDIZFromArchive(zipBridge(bridge), in.UploadDir, in.FilePath, in.FileName); err != nil && s.Config.Debug {
		log.Printf("[MASTER-ZS] zip diz refresh skipped for %s: %v", in.FilePath, err)
	}

	uploadMediaInfo := bridge.GetDirMediaInfo(in.UploadDir)
	mediaInfoFields := uploadMediaInfo
	if path.Clean(in.MediaInfoDir) != path.Clean(in.UploadDir) {
		mediaInfoFields = bridge.GetDirMediaInfo(in.MediaInfoDir)
	}
	state.HadAudioInfo = zipscript.AudioInfoLooksUsable(uploadMediaInfo)
	state.HadMediaInfo = releaseMediaInfoLooksUsable(mediaInfoFields)

	audioFields, err := applyAudioZipscriptChecksForDirWithCached(s, bridge, in.UploadDir, in.FilePath, in.FileName, uploadMediaInfo)
	if err != nil {
		log.Printf("[MASTER-ZS] post-upload audio check failed for %s: %v", in.FilePath, err)
	} else {
		state.AudioFields = cloneStringMap(audioFields)
	}
	state.MediaFields = probeSTORSitebotMediaInfo(s, bridge, in.MediaInfoDir, in.FilePath, in.FileName, state.HadMediaInfo)

	if subdir := zipscript.ReleaseSubdirLabel(s.Config.Zipscript, in.UploadDir); subdir != "" {
		state.EventData["release_subdir"] = subdir
		state.EventData["release_name"] = path.Base(path.Dir(in.UploadDir))
		if zipscript.IsIgnoredReleaseSubdir(s.Config.Zipscript, in.UploadDir) || !zipscript.AnnounceReleaseSubdirs(s.Config.Zipscript) {
			state.EventData["skip_release_announce"] = "true"
		}
	} else if zipscript.IsMultiDiscReleaseSubdir(in.UploadDir) {
		state.EventData["relname"] = zipscript.ReleaseDisplayName(in.UploadDir)
	}
	if state.SFVUpload && state.SFVEntries != nil {
		state.EventData["t_filecount"] = fmt.Sprintf("%d", len(state.SFVEntries))
		state.EventData["t_file_label"] = zipscript.ExpectedFileLabel(s.Config.Zipscript, in.UploadDir)
	}

	state.RaceUsers, state.RaceGroups, state.RaceTotalBytes, state.RaceTotalFiles, state.RaceDurationMs, state.RaceComplete = computeReleaseRaceSnapshot(s, bridge, in, state.EventData)
	state.ShouldAnnounceNR = shouldAnnounceNoRace(s.Config, in.UploadDir, append([]string(nil), in.ExistingNames...), in.FileName)
	return state
}

func verifyExistingPayloadsAfterSFVUpload(cfg *Config, bridge MasterBridge, dirPath string) {
	if cfg == nil || bridge == nil || !zipscript.ShouldDeleteBadCRCForDir(cfg.Zipscript, dirPath) {
		return
	}
	sfvEntries := bridge.GetSFVData(dirPath)
	if sfvEntries == nil {
		return
	}
	for _, entry := range bridge.ListDir(dirPath) {
		if entry.IsDir || entry.IsSymlink || strings.HasSuffix(strings.ToLower(entry.Name), ".sfv") {
			continue
		}
		expectedCRC, exists := zipscript.CachedExpectedCRC(sfvEntries, entry.Name)
		if !exists {
			continue
		}
		filePath := path.Join(dirPath, entry.Name)
		checksum, ok := bridge.GetKnownChecksum(filePath)
		if !ok || checksum == 0 {
			continue
		}
		if checksum == expectedCRC {
			clearMasterSFVMissingMarker(bridge, dirPath, entry.Name)
			continue
		}
		if err := bridge.DeleteFile(filePath); err != nil && !zipscript.IsNotFoundDeleteError(err) {
			log.Printf("[MASTER-ZS] CRC mismatch after SFV for %s: got %08X, expected %08X - delete failed: %v",
				entry.Name, checksum, expectedCRC, err)
			continue
		}
		_ = bridge.MarkFileMissing(filePath)
		createMasterSFVMissingMarker(cfg, bridge, dirPath, entry.Name)
		log.Printf("[MASTER-ZS] CRC mismatch after SFV for %s: got %08X, expected %08X - deleted",
			entry.Name, checksum, expectedCRC)
	}
}

func computeReleaseRaceSnapshot(s *Session, bridge MasterBridge, in releaseUploadPipelineInput, data map[string]string) ([]VFSRaceUser, []VFSRaceGroup, int64, int, int64, bool) {
	if s == nil || s.Config == nil || bridge == nil || !zipscript.RaceStatsOnSTORForDir(s.Config.Zipscript, in.UploadDir) {
		return nil, nil, 0, 0, 0, false
	}

	if strings.TrimSpace(in.FileName) != "" {
		bridge.NoteRacePayloadTransferAt(in.UploadDir, in.FileName, in.XferMs, in.CompletedAtMs)
	}

	trackedFile := in.FileName
	if strings.HasSuffix(strings.ToLower(in.FileName), ".sfv") {
		trackedFile = firstTrackedRaceFileName(bridge, in.UploadDir)
	}
	return populateUploadRaceData(bridge, s.Config, in.UploadDir, trackedFile, in.FileSize, data)
}

func emitReleaseUploadMetadata(s *Session, bridge MasterBridge, in releaseUploadPipelineInput, state releaseUploadPipelineState) {
	if state.AudioFields != nil {
		emitSTORSitebotAudioInfo(s, bridge, in.UploadDir, in.FilePath, in.FileName, in.TransferredBytes, in.SpeedMB, cloneStringMap(state.AudioFields), state.HadAudioInfo)
	}
	emitSTORSitebotMediaInfo(s, in.MediaInfoDir, in.FilePath, in.FileName, in.TransferredBytes, in.SpeedMB, state.MediaFields, state.HadMediaInfo)
}

func emitReleaseUploadEventAndRace(s *Session, bridge MasterBridge, in releaseUploadPipelineInput, state releaseUploadPipelineState) {
	userName := ""
	if s.User != nil {
		userName = s.User.Name
	}
	enrichUploadRaceUserData(state.EventData, state.RaceUsers, userName)
	s.emitEvent(EventUpload, in.FilePath, in.FileName, in.TransferredBytes, in.SpeedMB, state.EventData)

	if state.ShouldAnnounceNR && zipscript.RaceStatsOnSTORForDir(s.Config.Zipscript, in.UploadDir) {
		emitRaceEndAfter(s, in.UploadDir, nil, nil, in.FileSize, 1, 0, in.XferMs, 0)
		return
	}

	if useZipRaceMode(bridge, s.Config, in.UploadDir, in.FileName) {
		if state.RaceComplete && state.RaceTotalFiles > 0 {
			emitRaceEndAfter(s, in.UploadDir, state.RaceUsers, state.RaceGroups, state.RaceTotalBytes, state.RaceTotalFiles, state.RaceDurationMs, in.XferMs, zipscript.MediaInfoGraceDelayForDir(s.Config.Zipscript, in.UploadDir, in.FileName))
		}
		return
	}

	if state.SFVEntries == nil || !state.RaceComplete {
		return
	}
	// RaceComplete is already true here, so the release is verified complete. Emit
	// the COMPLETE on ANY file's hook in an eligible race dir -- not only when the
	// triggering file is the SFV or an SFV-listed file. Otherwise, if completeness
	// flipped true on a file whose hook computed it false (a transient flap), the
	// announce rode on a later trailing non-SFV file (cover/.m3u/.nfo) that the old
	// SFV-membership gate rejected, losing the COMPLETE for good. markRaceCompleteOnce
	// still dedups, and total/totalBytes count only SFV files so trailing files
	// don't change the dedup key.
	if state.SFVUpload || zipscript.RaceEndDirEligible(s.Config.Zipscript, in.UploadDir) {
		if err := bridge.SyncReleaseRaceStats(in.UploadDir); err != nil && s.Config.Debug {
			log.Printf("[MASTER-ZS] release race sync failed for %s: %v", in.UploadDir, err)
		}
		// Generate the audio .m3u from the SFV before the complete announce/hook fires,
		// so outbound races and link scripts always find it (like glftpd/pzs-ng).
		maybeGenerateReleaseM3U(s, bridge, in.UploadDir)
		if state.AudioFields == nil {
			emitOrPrimeReleaseAudioInfo(s, bridge, in.UploadDir)
		}
		emitRaceEndAfter(s, in.UploadDir, state.RaceUsers, state.RaceGroups, state.RaceTotalBytes, state.RaceTotalFiles, state.RaceDurationMs, in.XferMs, zipscript.MediaInfoGraceDelayForDir(s.Config.Zipscript, in.UploadDir, in.FileName))
	}
}

func queueMasterUploadPostHooks(s *Session, bridge MasterBridge, uploadDir, mediaInfoDir, filePath, fileName string, checksum uint32, transferredBytes, fileSize int64, speedMB float64, xferMs int64, existingNames []string) {
	if s == nil || s.Config == nil || bridge == nil {
		return
	}
	input := releaseUploadPipelineInput{
		UploadDir:        uploadDir,
		MediaInfoDir:     mediaInfoDir,
		FilePath:         filePath,
		FileName:         fileName,
		Checksum:         checksum,
		TransferredBytes: transferredBytes,
		FileSize:         fileSize,
		SpeedMB:          speedMB,
		XferMs:           xferMs,
		CompletedAtMs:    time.Now().UnixMilli(),
		ExistingNames:    append([]string(nil), existingNames...),
	}
	enqueueReleasePostHook(uploadDir, func() {
		runReleaseUploadPipeline(s, bridge, input)
	})
}

func zipscriptExistingNames(bridge MasterBridge, dirPath string) []string {
	return zipscriptExistingNamesFromEntries(bridge.ListDir(dirPath))
}

func zipscriptExistingNamesFromEntries(entries []MasterFileEntry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Name)
	}
	return out
}

func zipscriptExistingDirNames(bridge MasterBridge, dirPath string) []string {
	return zipscriptExistingDirNamesFromEntries(bridge.ListDir(dirPath))
}

func zipscriptExistingDirNamesFromEntries(entries []MasterFileEntry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir {
			out = append(out, entry.Name)
		}
	}
	return out
}

func isSampleMediaPath(filePath string) bool {
	lower := strings.ToLower(filePath)
	return strings.Contains(lower, "/sample/") || strings.Contains(lower, "/samples/") || strings.Contains(lower, ".sample.")
}

func normalizeReleaseMediaInfoFields(fields map[string]string) {
	if fields == nil {
		return
	}
	fields["year"] = normalizeReleaseMediaYear(fields["year"])
	fields["bitrate"] = normalizeReleaseMediaBitrate(fields["bitrate"])
	fields["sample_rate"] = normalizeReleaseMediaSampleRate(fields["sample_rate"])
	fields["channels"] = normalizeReleaseMediaChannels(fields["channels"])
	fields["duration"] = normalizeReleaseMediaDuration(fields["duration"])
}

func normalizeReleaseMediaYear(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 4 {
		year := s[:4]
		if _, err := strconv.Atoi(year); err == nil {
			return year
		}
	}
	return s
}

func normalizeReleaseMediaBitrate(s string) string {
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

func normalizeReleaseMediaSampleRate(s string) string {
	raw := strings.TrimSpace(s)
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "hz") {
		return strings.TrimSuffix(strings.TrimSuffix(lower, " hz"), "hz")
	}
	return raw
}

func normalizeReleaseMediaChannels(s string) string {
	switch strings.TrimSpace(s) {
	case "1":
		return "Mono"
	case "2":
		return "Stereo"
	case "6":
		return "5.1"
	case "8":
		return "7.1"
	default:
		return strings.TrimSpace(s)
	}
}

func normalizeReleaseMediaDuration(s string) string {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return raw
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "min") || strings.Contains(raw, ":") {
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

func releaseMediaInfoLooksUsable(fields map[string]string) bool {
	if len(fields) == 0 {
		return false
	}
	return strings.TrimSpace(firstNonEmptyMap(fields, "video_format", "audio_format", "duration", "width", "height")) != ""
}

func emitReleaseMetadataEvent(s *Session, evtType EventType, dirPath, filePath, fileName string, size int64, speedMB float64, fields map[string]string) {
	if s == nil || len(fields) == 0 {
		return
	}
	if evtType == EventMediaInfo {
		dirPath = storReleaseMediaDir(dirPath, filePath)
	}
	data := cloneStringMap(fields)
	if data == nil {
		data = map[string]string{}
	}
	data["filepath"] = filePath
	data["filename"] = fileName
	data["path"] = dirPath
	data["relname"] = zipscript.ReleaseDisplayName(dirPath)
	s.emitEvent(evtType, dirPath, path.Base(dirPath), size, speedMB, data)
}

func storReleaseMediaDir(uploadDir, filePath string) string {
	cleanFileDir := path.Dir(path.Clean(filePath))
	lowerFileBase := strings.ToLower(path.Base(cleanFileDir))
	if lowerFileBase == "sample" || lowerFileBase == "samples" {
		parent := path.Dir(cleanFileDir)
		if parent != "." && parent != "" {
			return parent
		}
	}
	cleanDir := path.Clean(uploadDir)
	if cleanDir == "." || cleanDir == "/" || cleanDir == "" {
		return cleanDir
	}
	lowerBase := strings.ToLower(path.Base(cleanDir))
	if lowerBase == "sample" || lowerBase == "samples" {
		parent := path.Dir(cleanDir)
		if parent != "." && parent != "" {
			return parent
		}
	}
	return cleanDir
}

func emitSTORSitebotAudioInfo(s *Session, bridge MasterBridge, dirPath, filePath, fileName string, size int64, speedMB float64, fields map[string]string, hadAudioInfo bool) {
	if hadAudioInfo || s == nil || bridge == nil || !zipscript.AudioInfoLooksUsable(fields) || !zipscript.ShowAudioInfoOnSTORForDir(s.Config.Zipscript, dirPath, fields) {
		return
	}
	if !bridge.ClaimReleaseMetadataAnnouncement(dirPath, "audioinfo") {
		return
	}
	emitReleaseMetadataEvent(s, EventAudioInfo, dirPath, filePath, fileName, size, speedMB, fields)
}

func emitOrPrimeReleaseAudioInfo(s *Session, bridge MasterBridge, dirPath string) {
	if s == nil || bridge == nil {
		return
	}
	fields := bridge.GetDirMediaInfo(dirPath)
	if zipscript.AudioInfoLooksUsable(fields) && zipscript.ShowAudioInfoOnSTORForDir(s.Config.Zipscript, dirPath, fields) {
		emitSTORSitebotAudioInfo(s, bridge, dirPath, dirPath, path.Base(dirPath), 0, 0, fields, false)
		return
	}

	entries := bridge.ListDir(dirPath)
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	for _, entry := range entries {
		if entry.IsDir || entry.IsSymlink {
			continue
		}
		ext := strings.ToLower(strings.TrimPrefix(path.Ext(entry.Name), "."))
		if ext != "mp3" && ext != "flac" && ext != "m4a" && ext != "wav" {
			continue
		}
		filePath := path.Join(dirPath, entry.Name)
		fields, err := applyAudioZipscriptChecksForDir(s, bridge, dirPath, filePath, entry.Name)
		if err != nil {
			if s.Config != nil && s.Config.Debug {
				log.Printf("[MASTER-ZS] release audio prime failed for %s: %v", filePath, err)
			}
			return
		}
		emitSTORSitebotAudioInfo(s, bridge, dirPath, filePath, entry.Name, entry.Size, 0, fields, false)
		return
	}
}

func probeSTORSitebotMediaInfo(s *Session, bridge MasterBridge, dirPath, filePath, fileName string, hadMediaInfo bool) map[string]string {
	if hadMediaInfo || s == nil || bridge == nil || s.Config == nil {
		if s != nil && s.Config != nil && s.Config.Debug && hadMediaInfo {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: release already has cached media info", filePath)
		}
		return nil
	}
	dirPath = storReleaseMediaDir(dirPath, filePath)
	if !mediaInfoReleaseDirAllowed(s.Config, dirPath) {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: %s is not a release dir", filePath, dirPath)
		}
		return nil
	}
	sections, sampleOnly, videoExts := mediaInfoPluginSettings(s.Config)
	section := sectionFromPathWithConfig(s.Config, dirPath)
	if len(sections) > 0 && !mediaInfoSectionMatch(section, sections) {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: section %q not enabled", filePath, section)
		}
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(fileName), "."))
	if !videoExts[ext] {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: extension %q not enabled", filePath, ext)
		}
		return nil
	}
	if sampleOnly && !isSampleMediaPath(filePath) {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: sample_only enabled and path is not a sample path", filePath)
		}
		return nil
	}
	fields, err := bridge.ProbeMediaInfo(filePath, "", 0)
	if err != nil {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: %v", filePath, err)
		}
		return nil
	}
	normalizeReleaseMediaInfoFields(fields)
	if !releaseMediaInfoLooksUsable(fields) {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] stor media probe skipped for %s: parser returned unusable metadata", filePath)
		}
		return nil
	}
	if s.Config.Debug {
		log.Printf("[MASTER-ZS] stor media probe emitted for %s: video=%q audio=%q width=%q height=%q duration=%q", filePath, strings.TrimSpace(fields["video_format"]), strings.TrimSpace(fields["audio_format"]), strings.TrimSpace(fields["width"]), strings.TrimSpace(fields["height"]), strings.TrimSpace(fields["duration"]))
	}
	bridge.CacheMediaInfo(dirPath, fields)
	return fields
}

func emitSTORSitebotMediaInfo(s *Session, dirPath, filePath, fileName string, size int64, speedMB float64, fields map[string]string, hadMediaInfo bool) {
	if hadMediaInfo || !releaseMediaInfoLooksUsable(fields) {
		return
	}
	dirPath = storReleaseMediaDir(dirPath, filePath)
	if s == nil || s.Config == nil || !mediaInfoReleaseDirAllowed(s.Config, dirPath) {
		return
	}
	emitReleaseMetadataEvent(s, EventMediaInfo, dirPath, filePath, fileName, size, speedMB, fields)
}

func mediaInfoReleaseDirAllowed(cfg *Config, dirPath string) bool {
	if cfg == nil {
		return false
	}
	cleanDir := path.Clean("/" + strings.TrimSpace(dirPath))
	if cleanDir == "/" || cleanDir == "." {
		return false
	}
	return zipscript.UsesRaceEntry(cfg.Zipscript, cleanDir)
}

func applyAudioZipscriptChecks(s *Session, bridge MasterBridge, filePath, fileName string) (map[string]string, error) {
	return applyAudioZipscriptChecksForDir(s, bridge, s.CurrentDir, filePath, fileName)
}

func applyAudioZipscriptChecksForDir(s *Session, bridge MasterBridge, dirPath, filePath, fileName string) (map[string]string, error) {
	return applyAudioZipscriptChecksForDirWithCached(s, bridge, dirPath, filePath, fileName, nil)
}

func applyAudioZipscriptChecksForDirWithCached(s *Session, bridge MasterBridge, dirPath, filePath, fileName string, cached map[string]string) (map[string]string, error) {
	if !zipscript.AudioCheckEnabled(s.Config.Zipscript, dirPath, fileName) {
		return nil, nil
	}
	if cached == nil {
		cached = bridge.GetDirMediaInfo(dirPath)
	}
	if zipscript.AudioInfoLooksUsable(cached) {
		return cached, nil
	}
	fields, err := bridge.ProbeMediaInfo(filePath, "", 0)
	if err != nil {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] audio probe skipped for %s: %v", filePath, err)
		}
		return nil, nil
	}
	if !zipscript.AudioInfoLooksUsable(fields) {
		if s.Config.Debug {
			log.Printf("[MASTER-ZS] audio probe for %s was not usable for release metadata", filePath)
		}
		return fields, nil
	}
	bridge.CacheMediaInfo(dirPath, fields)
	if reasons := zipscript.ValidateAudioRelease(s.Config.Zipscript, fields); len(reasons) > 0 {
		_ = bridge.DeleteFile(filePath)
		return nil, fmt.Errorf("%s", strings.Join(reasons, "; "))
	}
	if err := ensureAudioSortLinks(bridge, zipscript.AudioSortLinks(s.Config.Zipscript, dirPath, fields)); err != nil && s.Config.Debug {
		log.Printf("[MASTER-ZS] audio sort link failed for %s: %v", dirPath, err)
	}
	return fields, nil
}

func ensureUploadDirsForEvent(s *Session, bridge MasterBridge, uploadDir string) error {
	if s == nil || s.Config == nil || bridge == nil {
		return nil
	}
	releaseDir := path.Clean("/" + strings.TrimSpace(uploadDir))
	if releaseDir == "/" || releaseDir == "." {
		return nil
	}
	if subdir := zipscript.ReleaseSubdirLabel(s.Config.Zipscript, releaseDir); subdir != "" {
		releaseDir = path.Dir(releaseDir)
	}
	needNew := !bridge.FileExists(releaseDir)
	if needNew && s.Config.PluginManager != nil {
		// Mirror the explicit-MKD releaseguard check. Without this a STOR could
		// silently auto-create a banned release dir that an explicit MKD just
		// blocked (cbftp often falls through to STOR after a 550 on MKD).
		if err := s.Config.PluginManager.ValidateMKDir(s.User, releaseDir); err != nil {
			return err
		}
	}
	owner := "WeaveFTPd"
	group := "WeaveFTPd"
	if s.User != nil {
		if strings.TrimSpace(s.User.Name) != "" {
			owner = s.User.Name
		}
		if strings.TrimSpace(s.User.PrimaryGroup) != "" {
			group = s.User.PrimaryGroup
		}
	}
	if err := ensureDirPathOwned(bridge, uploadDir, owner, group); err != nil {
		return err
	}
	if needNew {
		if shouldStartRaceWindowForDir(s.Config, releaseDir) {
			startReleaseRaceWindow(bridge, releaseDir, time.Now().UnixMilli())
		}
		s.emitEvent(EventMKDir, releaseDir, path.Base(releaseDir), 0, 0, nil)
	}
	return nil
}
