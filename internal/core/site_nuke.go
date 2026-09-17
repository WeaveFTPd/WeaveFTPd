package core

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func (s *Session) HandleSiteNuke(args []string) bool {
	// Parse: SITE NUKE <dir> <x multiplier> [reason]
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE NUKE <dir> <xN> [reason]\r\n")
		return false
	}

	target := args[0]
	multiplierStr := strings.TrimPrefix(strings.ToLower(args[1]), "x")
	multiplier, err := strconv.Atoi(multiplierStr)
	if err != nil || multiplier <= 0 {
		fmt.Fprintf(s.Conn, "501 Invalid multiplier (use x1, x2, x10, etc).\r\n")
		return false
	}

	// Check max multiplier
	if multiplier > s.Config.NukeMaxMultiplier {
		fmt.Fprintf(s.Conn, "550 Multiplier exceeds max (%d).\r\n", s.Config.NukeMaxMultiplier)
		return false
	}

	reason := "No reason"
	if len(args) > 2 {
		reason = strings.Join(args[2:], " ")
	}

	if bridge, ok := s.masterBridge(); ok {
		return s.handleSiteNukeVFS(bridge, target, multiplier, reason)
	}

	// Get target directory
	targetPath := target
	if !strings.HasPrefix(targetPath, "/") {
		targetPath = path.Join(s.CurrentDir, targetPath)
	}
	targetPath = path.Clean(targetPath)
	aclPath := path.Join(s.Config.ACLBasePath, path.Clean(targetPath))
	if !s.ACLEngine.CanPerform(s.User, "NUKE", aclPath) {
		fmt.Fprintf(s.Conn, "550 Insufficient flags.\r\n")
		return false
	}
	// Use the resolved targetPath (honors an absolute /-target), the same path
	// the ACL was checked against, not CurrentDir+target, which would nuke the
	// wrong dir for absolute targets.
	fullPath := filepath.Join(s.Config.StoragePath, targetPath)
	dirName := filepath.Base(fullPath)

	// Scan files and collect uploader info
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Cannot read directory.\r\n")
		return false
	}

	// Map: username -> total_bytes
	uploaderBytes := make(map[string]int64)

	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Get file owner
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		username := GetUsernameByUID(int(stat.Uid), s.Config)
		uploaderBytes[username] += info.Size()
	}

	nukeeLine := FormatNukees(BuildNukeUserStats(uploaderBytes), []string{"weaveftpd", s.User.Name})

	// Rename first so a failed rename never leaves users penalized for a dir that
	// wasn't actually nuked (which a retry would then double-penalize).
	newName := fmt.Sprintf("[NUKED]-%s", dirName)
	newPath := filepath.Join(filepath.Dir(fullPath), newName)
	newSitePath := path.Join(path.Dir(targetPath), newName)

	if err := os.Rename(fullPath, newPath); err != nil {
		fmt.Fprintf(s.Conn, "550 Rename failed: %v\r\n", err)
		return false
	}

	// Apply the penalty, recording exactly what was removed from each user.
	totalNuked, nukeeRecords := ApplyNukeCredits(s.GroupMap, uploaderBytes, multiplier)
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		if err := db.RecordNuke(NukeHistoryEntry{
			OriginalPath:        targetPath,
			CurrentPath:         newSitePath,
			ReleaseName:         dirName,
			Multiplier:          multiplier,
			Reason:              reason,
			NukedBy:             s.User.Name,
			UsersAffected:       len(uploaderBytes),
			TotalBytes:          SumBytes(uploaderBytes),
			TotalCreditsRemoved: totalNuked,
			Nukees:              nukeeLine,
			NukeesData:          EncodeNukeeRecords(nukeeRecords),
		}); err != nil && s.Config.Debug {
			log.Printf("[NUKE-DB] record local nuke failed for %s: %v", targetPath, err)
		}
	} else if s.Config.Debug {
		log.Printf("[NUKE-DB] init failed: %v", err)
	}

	s.emitEvent(EventNuke, path.Join(s.CurrentDir, target), dirName, 0, 0, map[string]string{
		"multiplier": strconv.Itoa(multiplier),
		"reason":     reason,
		"users":      strconv.Itoa(len(uploaderBytes)),
		"nukees":     nukeeLine,
	})
	totalMB := BytesToMB(SumBytes(uploaderBytes))
	fmt.Fprintf(s.Conn, "200 Nuked: x%d multiplier, %d MB, %d users affected, %d credits removed. Reason: %s\r\n",
		multiplier, totalMB, len(uploaderBytes), totalNuked, reason)
	return false
}

func (s *Session) HandleSiteUnnuke(args []string) bool {
	// Parse: SITE UNNUKE <dir> [reason]
	if len(args) < 1 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE UNNUKE <dir> [reason]\r\n")
		return false
	}

	target := args[0]
	if bridge, ok := s.masterBridge(); ok {
		return s.handleSiteUnnukeVFS(bridge, target)
	}

	targetPath := target
	if !strings.HasPrefix(targetPath, "/") {
		targetPath = path.Join(s.CurrentDir, targetPath)
	}
	targetPath = path.Clean(targetPath)
	aclPath := path.Join(s.Config.ACLBasePath, targetPath)
	if !s.ACLEngine.CanPerform(s.User, "UNNUKE", aclPath) {
		fmt.Fprintf(s.Conn, "550 Insufficient flags.\r\n")
		return false
	}
	fullPath := filepath.Join(s.Config.StoragePath, targetPath)
	dirName := filepath.Base(fullPath)

	// Check if directory is nuked
	if !strings.HasPrefix(dirName, "[NUKED]-") {
		fmt.Fprintf(s.Conn, "550 Directory is not nuked.\r\n")
		return false
	}

	// Extract original name
	originalName := strings.TrimPrefix(dirName, "[NUKED]-")
	newPath := filepath.Join(filepath.Dir(fullPath), originalName)

	// Scan files to restore credits
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Cannot read directory.\r\n")
		return false
	}

	uploaderBytes := make(map[string]int64)
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		username := GetUsernameByUID(int(stat.Uid), s.Config)
		uploaderBytes[username] += info.Size()
	}

	var storedRecords map[string]NukeeRecord
	restoreMultiplier := 0
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		if entry, err := db.FindActiveByPath(targetPath); err == nil && entry != nil {
			restoreMultiplier = entry.Multiplier
			storedRecords = DecodeNukeeRecords(entry.NukeesData)
		}
	}

	// Rename back first; restore credits only after the state transition succeeds.
	if err := os.Rename(fullPath, newPath); err != nil {
		fmt.Fprintf(s.Conn, "550 Rename failed: %v\r\n", err)
		return false
	}

	var totalRestored int64
	if len(storedRecords) > 0 {
		totalRestored = ApplyUnnukeCredits(s.GroupMap, storedRecords)
	} else {
		// Pre-records nuke or DB miss: recompute at the actual multiplier (never the
		// configured max), defaulting to x1 when unknown so we can't over-restore.
		totalRestored = ApplyUnnukeCreditsRecompute(s.GroupMap, uploaderBytes, restoreMultiplier)
	}
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		if _, err := db.MarkUnnuked(targetPath, path.Join(path.Dir(targetPath), originalName), s.User.Name, totalRestored); err != nil && !errors.Is(err, sql.ErrNoRows) && s.Config.Debug {
			log.Printf("[NUKE-DB] mark local unnuke failed for %s: %v", targetPath, err)
		}
	} else if s.Config.Debug {
		log.Printf("[NUKE-DB] init failed: %v", err)
	}

	s.emitEvent(EventUnnuke, newPath, originalName, 0, 0, map[string]string{
		"users": strconv.Itoa(len(uploaderBytes)),
	})
	totalMB := BytesToMB(SumBytes(uploaderBytes))
	fmt.Fprintf(s.Conn, "200 Unnuked: %d MB, %d users affected, %d credits restored.\r\n",
		totalMB, len(uploaderBytes), totalRestored)
	return false
}

func (s *Session) HandleSiteNukes(args []string) bool {
	query := ""
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		query = strings.TrimSpace(strings.Join(args, " "))
	}
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		entries, err := db.List(query, siteSearchLimit)
		if err == nil {
			if bridge, ok := s.masterBridge(); ok {
				entries = s.pruneMissingActiveNukeHistory(bridge, db, entries)
			}
			fmt.Fprintf(s.Conn, "200- Nuke history (%d):\r\n", len(entries))
			for _, entry := range entries {
				line := fmt.Sprintf("[%s] %s x%d by %s at %s :: %s :: %d users :: %s",
					strings.ToUpper(entry.Status),
					entry.OriginalPath,
					entry.Multiplier,
					entry.NukedBy,
					formatUnixTime(entry.NukedAt),
					formatBytes(entry.TotalBytes),
					entry.UsersAffected,
					formatBytes(entry.TotalCreditsRemoved),
				)
				if strings.TrimSpace(entry.Reason) != "" {
					line += " :: " + entry.Reason
				}
				if strings.TrimSpace(entry.Nukees) != "" {
					line += " :: " + entry.Nukees
				}
				if entry.Status == "unnuked" && strings.TrimSpace(entry.RestoredPath) != "" {
					line += fmt.Sprintf(" :: restored by %s to %s (%s)", entry.UnnukedBy, entry.RestoredPath, formatBytes(entry.TotalCreditsRestored))
				}
				fmt.Fprintf(s.Conn, "200- %s\r\n", line)
			}
			fmt.Fprintf(s.Conn, "200 End of NUKES\r\n")
			return false
		}
	}

	if bridge, ok := s.masterBridge(); ok {
		fallbackQuery := "[NUKED]-"
		if strings.TrimSpace(query) != "" {
			fallbackQuery = query
		}
		results := bridge.SearchDirs(fallbackQuery, siteSearchLimit)
		var nuked []string
		for _, result := range results {
			if strings.HasPrefix(path.Base(result.Path), "[NUKED]-") {
				nuked = append(nuked, result.Path)
			}
		}
		sort.Strings(nuked)
		fmt.Fprintf(s.Conn, "200- Nuked releases (%d):\r\n", len(nuked))
		for _, item := range nuked {
			fmt.Fprintf(s.Conn, "200- %s\r\n", item)
		}
		fmt.Fprintf(s.Conn, "200 End of NUKES\r\n")
		return false
	}

	base := filepath.Join(s.Config.StoragePath, s.CurrentDir)
	var nuked []string
	entries, err := os.ReadDir(base)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "[NUKED]-") {
				nuked = append(nuked, path.Join(s.CurrentDir, entry.Name()))
			}
		}
	}
	sort.Strings(nuked)
	fmt.Fprintf(s.Conn, "200- Nuked releases (%d):\r\n", len(nuked))
	for _, item := range nuked {
		fmt.Fprintf(s.Conn, "200- %s\r\n", item)
	}
	fmt.Fprintf(s.Conn, "200 End of NUKES\r\n")
	return false
}

func (s *Session) pruneMissingActiveNukeHistory(bridge MasterBridge, db *NukeHistoryDB, entries []NukeHistoryEntry) []NukeHistoryEntry {
	if bridge == nil || db == nil {
		return entries
	}
	out := entries[:0]
	for _, entry := range entries {
		if strings.EqualFold(entry.Status, "active") && !nukeHistoryEntryExists(bridge, entry) {
			if _, err := db.MarkDeleted(entry.CurrentPath); err != nil && !errors.Is(err, sql.ErrNoRows) && s != nil && s.Config != nil && s.Config.Debug {
				log.Printf("[NUKE-DB] mark deleted failed for %s: %v", entry.CurrentPath, err)
			}
			continue
		}
		out = append(out, entry)
	}
	return out
}

func nukeHistoryEntryExists(bridge MasterBridge, entry NukeHistoryEntry) bool {
	if bridge == nil {
		return false
	}
	candidate := strings.TrimSpace(entry.CurrentPath)
	if candidate == "" {
		candidate = strings.TrimSpace(entry.OriginalPath)
	}
	return candidate != "" && bridge.FileExists(candidate)
}

func (s *Session) handleSiteNukeVFS(bridge MasterBridge, target string, multiplier int, reason string) bool {
	dirPath, ok := s.resolveSiteDir(bridge, target, false)
	if !ok {
		return false
	}
	dirName := path.Base(dirPath)
	if strings.HasPrefix(dirName, "[NUKED]-") {
		fmt.Fprintf(s.Conn, "550 Directory is already nuked: %s\r\n", dirPath)
		return false
	}
	aclPath := path.Join(s.Config.ACLBasePath, dirPath)
	if !s.ACLEngine.CanPerform(s.User, "NUKE", aclPath) {
		fmt.Fprintf(s.Conn, "550 Insufficient flags for %s.\r\n", dirPath)
		return false
	}

	uploaderBytes := DirUploaderBytes(bridge, dirPath)
	nukeeLine := FormatNukees(BuildNukeUserStats(uploaderBytes), []string{"weaveftpd", s.User.Name})
	result, err := PerformSystemNuke(bridge, s.GroupMap, dirPath, multiplier, reason, "[NUKED]-")
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Nuke failed: %v\r\n", err)
		return false
	}
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		if err := db.RecordNuke(NukeHistoryEntry{
			OriginalPath:        dirPath,
			CurrentPath:         result.NewPath,
			ReleaseName:         result.ReleaseName,
			Multiplier:          multiplier,
			Reason:              reason,
			NukedBy:             s.User.Name,
			UsersAffected:       result.UsersAffected,
			TotalBytes:          SumBytes(uploaderBytes),
			TotalCreditsRemoved: result.TotalCreditsRemoved,
			Nukees:              nukeeLine,
			NukeesData:          EncodeNukeeRecords(result.NukeeRecords),
		}); err != nil && s.Config.Debug {
			log.Printf("[NUKE-DB] record master nuke failed for %s: %v", dirPath, err)
		}
	} else if s.Config.Debug {
		log.Printf("[NUKE-DB] init failed: %v", err)
	}

	s.emitEvent(EventNuke, dirPath, dirName, 0, 0, map[string]string{
		"multiplier": strconv.Itoa(multiplier),
		"reason":     reason,
		"users":      strconv.Itoa(result.UsersAffected),
		"nukees":     nukeeLine,
	})
	fmt.Fprintf(s.Conn, "200 Nuked %s: x%d multiplier, %d MB, %d users affected, %d credits removed. Reason: %s\r\n",
		dirPath, multiplier, BytesToMB(SumBytes(uploaderBytes)), result.UsersAffected, result.TotalCreditsRemoved, reason)
	return false
}

func (s *Session) handleSiteUnnukeVFS(bridge MasterBridge, target string) bool {
	dirPath, ok := s.resolveSiteDir(bridge, target, true)
	if !ok {
		return false
	}
	dirName := path.Base(dirPath)
	if !strings.HasPrefix(dirName, "[NUKED]-") {
		fmt.Fprintf(s.Conn, "550 Directory is not nuked: %s\r\n", dirPath)
		return false
	}
	aclPath := path.Join(s.Config.ACLBasePath, dirPath)
	if !s.ACLEngine.CanPerform(s.User, "UNNUKE", aclPath) {
		fmt.Fprintf(s.Conn, "550 Insufficient flags for %s.\r\n", dirPath)
		return false
	}

	uploaderBytes := DirUploaderBytes(bridge, dirPath)
	var storedRecords map[string]NukeeRecord
	restoreMultiplier := 0
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		if entry, err := db.FindActiveByPath(dirPath); err == nil && entry != nil {
			restoreMultiplier = entry.Multiplier
			storedRecords = DecodeNukeeRecords(entry.NukeesData)
		}
	}

	// Rename first: only restore credits once the state transition has actually
	// happened, so a failed rename can never leave users credited for a still-nuked
	// dir (which a retry would then double-credit).
	originalName := strings.TrimPrefix(dirName, "[NUKED]-")
	if err := bridge.RenameFile(dirPath, path.Dir(dirPath), originalName); err != nil {
		fmt.Fprintf(s.Conn, "550 Unnuke rename failed: %v\r\n", err)
		return false
	}

	var totalRestored int64
	if len(storedRecords) > 0 {
		// Exact inverse: restore precisely what was removed.
		totalRestored = ApplyUnnukeCredits(s.GroupMap, storedRecords)
	} else {
		// Pre-records nuke (or DB miss): recompute at the actual multiplier, never
		// the configured max. Defaults to x1 when the multiplier is unknown so we
		// can't over-restore.
		totalRestored = ApplyUnnukeCreditsRecompute(s.GroupMap, uploaderBytes, restoreMultiplier)
	}

	newPath := path.Join(path.Dir(dirPath), originalName)
	if db, err := GetNukeHistoryDB(s.Config.Debug); err == nil {
		if _, err := db.MarkUnnuked(dirPath, newPath, s.User.Name, totalRestored); err != nil && !errors.Is(err, sql.ErrNoRows) && s.Config.Debug {
			log.Printf("[NUKE-DB] mark master unnuke failed for %s: %v", dirPath, err)
		}
	} else if s.Config.Debug {
		log.Printf("[NUKE-DB] init failed: %v", err)
	}
	s.emitEvent(EventUnnuke, newPath, originalName, 0, 0, map[string]string{
		"users": strconv.Itoa(len(uploaderBytes)),
	})
	fmt.Fprintf(s.Conn, "200 Unnuked %s: %d MB, %d users affected, %d credits restored.\r\n",
		dirPath, BytesToMB(SumBytes(uploaderBytes)), len(uploaderBytes), totalRestored)
	return false
}

func (s *Session) masterBridge() (MasterBridge, bool) {
	if s.Config == nil || s.Config.Mode != "master" || s.MasterManager == nil {
		return nil, false
	}
	bridge, ok := s.MasterManager.(MasterBridge)
	return bridge, ok
}

func (s *Session) resolveSiteDir(bridge MasterBridge, target string, wantNuked bool) (string, bool) {
	return resolveSiteDirPath(s.Conn, s.CurrentDir, target, wantNuked, bridge.FileExists, bridge.SearchDirs)
}

func resolveSiteDirPath(w io.Writer, currentDir, target string, wantNuked bool, fileExists func(string) bool, searchDirs func(string, int) []VFSSearchResult) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		writeSiteDirResolveError(w, "550 Missing directory.\r\n")
		return "", false
	}
	absoluteTarget := strings.HasPrefix(target, "/")
	candidate := target
	if !absoluteTarget {
		candidate = path.Join(currentDir, candidate)
	}
	candidate = path.Clean(candidate)
	if fileExists != nil && fileExists(candidate) {
		if dirNukeStateOK(candidate, wantNuked) {
			return candidate, true
		}
		if wantNuked {
			writeSiteDirResolveError(w, "550 Directory is not nuked: %s\r\n", candidate)
		} else {
			writeSiteDirResolveError(w, "550 Directory is already nuked: %s\r\n", candidate)
		}
		return "", false
	}
	if absoluteTarget {
		writeSiteDirResolveError(w, "550 Directory not found: %s\r\n", candidate)
		return "", false
	}

	query := strings.TrimPrefix(path.Base(target), "[NUKED]-")
	var results []VFSSearchResult
	if searchDirs != nil {
		results = searchDirs(query, siteSearchLimit)
	}
	matches := make([]VFSSearchResult, 0, len(results))
	for _, result := range results {
		if !dirNukeStateOK(result.Path, wantNuked) {
			continue
		}
		base := path.Base(result.Path)
		cleanBase := strings.TrimPrefix(base, "[NUKED]-")
		if strings.EqualFold(base, target) || strings.EqualFold(cleanBase, target) || strings.EqualFold(cleanBase, query) {
			matches = append(matches, result)
		}
	}
	if len(matches) == 1 {
		return path.Clean(matches[0].Path), true
	}
	if len(matches) == 0 {
		writeSiteDirResolveError(w, "550 Directory not found. Try SITE SEARCH %s\r\n", query)
		return "", false
	}
	writeSiteDirResolveError(w, "550- Multiple matches for %s; use the full path:\r\n", query)
	for i, match := range matches {
		if i >= 10 {
			writeSiteDirResolveError(w, "550- ... and %d more\r\n", len(matches)-i)
			break
		}
		writeSiteDirResolveError(w, "550- %s\r\n", match.Path)
	}
	writeSiteDirResolveError(w, "550 Ambiguous directory.\r\n")
	return "", false
}

func (s *Session) dirNukeStateOK(dirPath string, wantNuked bool) bool {
	return dirNukeStateOK(dirPath, wantNuked)
}

func dirNukeStateOK(dirPath string, wantNuked bool) bool {
	isNuked := strings.HasPrefix(path.Base(dirPath), "[NUKED]-")
	return isNuked == wantNuked
}

func writeSiteDirResolveError(w io.Writer, format string, args ...interface{}) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...)
}
