package autonuke

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	pluginpkg "weaveftpd/internal/plugin"
)

type Handler struct {
	svc        *pluginpkg.Services
	debug      bool
	cfg        config
	siteRunner func(siteArgs string) ([]string, error)
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

type config struct {
	ScanIntervalSeconds int
	Host                string
	Port                int
	User                string
	Password            string
	UseTLS              bool
	Insecure            bool
	TimeoutSeconds      int
	StateDir            string
	NukedPrefix         string
	Sections            []string
	AffilsDirs          []string
	Excludes            []string
	ApprovalMarkers     []string
	CheckCompleteDir    bool
	UserExclude         string
	Empty               timedRule
	HalfEmpty           timedPayloadRule
	Incomplete          incompleteRule
	Banned              timedPatternRules
	Allowed             timedPatternRules
	DeleteNukes         deleteRule
}

type timedRule struct {
	Enabled         bool
	WarnEnabled     bool
	WarnAfterMin    int
	NukeAfterMin    int
	Multiplier      int
	Reason          string
	WarnTag         string
	WarnDescription string
}

type timedPayloadRule struct {
	timedRule
	PayloadExtensions []string
}

type incompleteRule struct {
	timedRule
	JumpOn []string
}

type timedPatternRules struct {
	Enabled         bool
	WarnEnabled     bool
	WarnAfterMin    int
	NukeAfterMin    int
	DefaultMulti    int
	WarnTag         string
	WarnDescription string
	Rules           []patternRule
}

type patternRule struct {
	BasePath    string
	Patterns    []string
	Multiplier  int
	Description string
}

type deleteRule struct {
	Enabled        bool
	DeleteAfterMin int
}

type releaseCandidate struct {
	Path    string
	Name    string
	Section string
	Owner   string
	ModTime int64
}

type fileInfo struct {
	Path      string
	Name      string
	IsDir     bool
	IsSymlink bool
	Link      string
	ModTime   int64
}

type historyEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Path      string `json:"path,omitempty"`
	Name      string `json:"name,omitempty"`
	Section   string `json:"section,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func New() *Handler {
	return &Handler{stopCh: make(chan struct{})}
}

func (h *Handler) Name() string { return "autonuke" }

func (h *Handler) Init(svc *pluginpkg.Services, raw map[string]interface{}) error {
	h.svc = svc
	if v, ok := raw["debug"].(bool); ok {
		h.debug = v
	} else if svc != nil {
		h.debug = svc.Debug
	}
	h.cfg = loadConfig(raw)
	if h.svc == nil || h.svc.Bridge == nil {
		h.logf("bridge unavailable, plugin idle")
		return nil
	}
	if strings.TrimSpace(h.cfg.User) == "" || h.cfg.Password == "" {
		return fmt.Errorf("autonuke requires user/password so it can run normal SITE NUKE")
	}
	if len(h.cfg.Sections) == 0 {
		h.logf("no sections configured, plugin idle")
		return nil
	}
	if err := os.MkdirAll(h.cfg.StateDir, 0755); err != nil {
		return fmt.Errorf("autonuke state_dir %q: %w", h.cfg.StateDir, err)
	}
	h.wg.Add(1)
	go h.loop()
	h.logf("initialized interval=%ds sections=%d state_dir=%s", h.cfg.ScanIntervalSeconds, len(h.cfg.Sections), h.cfg.StateDir)
	return nil
}

func (h *Handler) OnEvent(evt *pluginpkg.Event) error { return nil }

func (h *Handler) Stop() error {
	h.stopOnce.Do(func() { close(h.stopCh) })
	h.wg.Wait()
	return nil
}

func (h *Handler) loop() {
	defer h.wg.Done()
	ticker := time.NewTicker(time.Duration(h.cfg.ScanIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.runOnce()
		}
	}
}

func (h *Handler) runOnce() {
	lockPath := path.Join(h.cfg.StateDir, "autonuke.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			h.logf("lock create failed: %v", err)
		}
		return
	}
	_, _ = fmt.Fprintf(lockFile, "%d\n", os.Getpid())
	_ = lockFile.Close()
	defer os.Remove(lockPath)

	for _, rel := range h.listReleaseCandidates() {
		h.processRelease(rel)
	}
	if h.cfg.DeleteNukes.Enabled {
		h.cleanupOldNukes()
	}
}

func (h *Handler) processRelease(rel releaseCandidate) {
	if h.isProtectedBase(rel.Path) {
		h.logf("skipping section base %s from autonuke scan", rel.Path)
		h.appendHistory("skip_section_base", rel, "section base", "")
		h.clearAllWarnings(rel)
		return
	}
	if isDatedBucketName(rel.Name) {
		h.logf("skipping dated bucket %s from autonuke scan", rel.Path)
		h.appendHistory("skip_dated_bucket", rel, "dated bucket", "")
		h.clearAllWarnings(rel)
		return
	}
	if h.skipRelease(rel) {
		h.clearAllWarnings(rel)
		return
	}
	if h.handleBanned(rel) {
		return
	}
	if h.hasApprovalMarker(rel.Path) {
		h.clearAllWarnings(rel)
		return
	}
	if h.handleEmpty(rel) {
		return
	}
	if h.handleIncomplete(rel) {
		return
	}
	if h.handleHalfEmpty(rel) {
		return
	}
	if h.handleAllowed(rel) {
		return
	}
	h.clearAllWarnings(rel)
}

func (h *Handler) listReleaseCandidates() []releaseCandidate {
	seen := make(map[string]releaseCandidate)
	for _, pattern := range h.currentSectionPatterns() {
		for _, rel := range h.expandPattern(path.Clean(pattern)) {
			seen[rel.Path] = rel
		}
	}
	out := make([]releaseCandidate, 0, len(seen))
	for _, rel := range seen {
		out = append(out, rel)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (h *Handler) expandPattern(pattern string) []releaseCandidate {
	if strings.HasSuffix(pattern, "/*/*") {
		base := strings.TrimSuffix(pattern, "/*/*")
		out := []releaseCandidate{}
		for _, parent := range h.svc.Bridge.PluginListDir(base) {
			if !parent.IsDir || parent.IsSymlink || strings.HasPrefix(parent.Name, ".") {
				continue
			}
			parentPath := path.Join(base, parent.Name)
			for _, rel := range h.svc.Bridge.PluginListDir(parentPath) {
				if !rel.IsDir || rel.IsSymlink || strings.HasPrefix(rel.Name, ".") {
					continue
				}
				out = append(out, releaseCandidate{
					Path:    path.Join(parentPath, rel.Name),
					Name:    rel.Name,
					Section: sectionFromPath(parentPath),
					Owner:   rel.Owner,
					ModTime: rel.ModTime,
				})
			}
		}
		return out
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(pattern, "/*")
		out := []releaseCandidate{}
		for _, rel := range h.svc.Bridge.PluginListDir(base) {
			if !rel.IsDir || rel.IsSymlink || strings.HasPrefix(rel.Name, ".") {
				continue
			}
			if isDatedBucketName(rel.Name) {
				parentPath := path.Join(base, rel.Name)
				for _, child := range h.svc.Bridge.PluginListDir(parentPath) {
					if !child.IsDir || child.IsSymlink || strings.HasPrefix(child.Name, ".") {
						continue
					}
					out = append(out, releaseCandidate{
						Path:    path.Join(parentPath, child.Name),
						Name:    child.Name,
						Section: sectionFromPath(parentPath),
						Owner:   child.Owner,
						ModTime: child.ModTime,
					})
				}
				continue
			}
			out = append(out, releaseCandidate{
				Path:    path.Join(base, rel.Name),
				Name:    rel.Name,
				Section: sectionFromPath(base),
				Owner:   rel.Owner,
				ModTime: rel.ModTime,
			})
		}
		return out
	}
	return nil
}

func (h *Handler) skipRelease(rel releaseCandidate) bool {
	if strings.HasPrefix(rel.Name, h.cfg.NukedPrefix) {
		return true
	}
	if db, err := core.GetNukeHistoryDB(false); err == nil && db != nil {
		if entry, err := db.FindActiveByPath(rel.Path); err == nil && entry != nil {
			return true
		}
	}
	nameLower := strings.ToLower(rel.Name)
	for _, token := range h.excludeTokens() {
		if token != "" && strings.Contains(nameLower, strings.ToLower(token)) {
			return true
		}
	}
	return false
}

func (h *Handler) hasApprovalMarker(dirPath string) bool {
	entries := h.svc.Bridge.PluginListDir(dirPath)
	for _, entry := range entries {
		name := strings.ToLower(entry.Name)
		for _, marker := range h.cfg.ApprovalMarkers {
			if marker != "" && strings.Contains(name, strings.ToLower(marker)) {
				return true
			}
		}
		if h.cfg.CheckCompleteDir && entry.IsDir && strings.EqualFold(entry.Name, "complete") {
			return true
		}
	}
	return false
}

func (h *Handler) ageMinutes(rel releaseCandidate) int {
	if rel.ModTime <= 0 {
		return 0
	}
	return int(time.Since(time.Unix(rel.ModTime, 0)).Minutes())
}

func (h *Handler) handleEmpty(rel releaseCandidate) bool {
	rule := h.cfg.Empty
	if !rule.Enabled {
		h.clearWarning(rel, "empty")
		return false
	}
	if len(visibleEntries(h.svc.Bridge.PluginListDir(rel.Path))) != 0 {
		h.clearWarning(rel, "empty")
		return false
	}
	return h.applyTimedRule(rel, "empty", rule, timedNukeReason(rule.Reason, rule.NukeAfterMin), "")
}

func (h *Handler) handleHalfEmpty(rel releaseCandidate) bool {
	rule := h.cfg.HalfEmpty
	if !rule.Enabled {
		h.clearWarning(rel, "halfempty")
		return false
	}
	files := h.walkVisibleFiles(rel.Path, 3)
	if len(files) == 0 {
		h.clearWarning(rel, "halfempty")
		return false
	}
	for _, file := range files {
		ext := strings.TrimPrefix(strings.ToLower(path.Ext(file.Name)), ".")
		for _, allowed := range rule.PayloadExtensions {
			if ext == strings.TrimPrefix(strings.ToLower(allowed), ".") {
				h.clearWarning(rel, "halfempty")
				return false
			}
		}
	}
	return h.applyTimedRule(rel, "halfempty", rule.timedRule, timedNukeReason(rule.Reason, rule.NukeAfterMin), "")
}

func (h *Handler) handleIncomplete(rel releaseCandidate) bool {
	rule := h.cfg.Incomplete
	if !rule.Enabled {
		h.clearWarning(rel, "incomplete")
		return false
	}
	if !h.isReleaseIncomplete(rel.Path, rule.JumpOn) {
		h.clearWarning(rel, "incomplete")
		return false
	}
	return h.applyTimedRule(rel, "incomplete", rule.timedRule, timedNukeReason(rule.Reason, rule.NukeAfterMin), "")
}

func (h *Handler) handleBanned(rel releaseCandidate) bool {
	rules := h.cfg.Banned
	if !rules.Enabled {
		h.clearWarning(rel, "banned")
		return false
	}
	for _, rule := range rules.Rules {
		if !pathHasBase(rel.Path, rule.BasePath) {
			continue
		}
		match := firstPatternHit(rel.Name, rule.Patterns)
		if match == "" {
			continue
		}
		reason := fmt.Sprintf("%s not allowed", match)
		if rule.Description != "" {
			reason = fmt.Sprintf("%s: banned word %s", rule.Description, match)
		}
		return h.applyPatternRule(rel, "banned", rules, rule.MultiplierOr(rules.DefaultMulti), reason, match)
	}
	h.clearWarning(rel, "banned")
	return false
}

func (h *Handler) handleAllowed(rel releaseCandidate) bool {
	rules := h.cfg.Allowed
	if !rules.Enabled || len(rules.Rules) == 0 {
		h.clearWarning(rel, "allowed")
		return false
	}
	for _, rule := range rules.Rules {
		if !pathHasBase(rel.Path, rule.BasePath) {
			continue
		}
		if firstPatternHit(rel.Name, rule.Patterns) != "" {
			h.clearWarning(rel, "allowed")
			return false
		}
		reason := "release name not allowed"
		if rule.Description != "" {
			reason = rule.Description
		}
		return h.applyPatternRule(rel, "allowed", rules, rule.MultiplierOr(rules.DefaultMulti), reason, "")
	}
	h.clearWarning(rel, "allowed")
	return false
}

func (h *Handler) applyTimedRule(rel releaseCandidate, key string, rule timedRule, reason string, detail string) bool {
	age := h.ageMinutes(rel)
	if age >= rule.NukeAfterMin && rule.NukeAfterMin > 0 {
		h.clearWarning(rel, key)
		return h.nuke(rel, rule.Multiplier, reason)
	}
	if rule.WarnEnabled && age >= rule.WarnAfterMin && rule.WarnAfterMin > 0 {
		h.warn(rel, key, rule.WarnTag, rule.WarnDescription, rule.WarnAfterMin, rule.NukeAfterMin, detail)
		return true
	} else {
		h.clearWarning(rel, key)
	}
	return false
}

func (h *Handler) applyPatternRule(rel releaseCandidate, key string, rules timedPatternRules, multiplier int, reason string, detail string) bool {
	age := h.ageMinutes(rel)
	if age >= rules.NukeAfterMin && rules.NukeAfterMin > 0 {
		h.clearWarning(rel, key)
		return h.nuke(rel, multiplier, reason)
	}
	if rules.WarnEnabled && age >= rules.WarnAfterMin && rules.WarnAfterMin > 0 {
		h.warn(rel, key, rules.WarnTag, rules.WarnDescription, rules.WarnAfterMin, rules.NukeAfterMin, detail)
		return true
	} else {
		h.clearWarning(rel, key)
	}
	return false
}

func (h *Handler) warn(rel releaseCandidate, key, tag, description string, warnAfter, nukeAfter int, detail string) {
	warnPath := h.warningFile(rel, key)
	if _, err := os.Stat(warnPath); err == nil {
		return
	}
	payload := []string{
		fmt.Sprintf("path=%s", rel.Path),
		fmt.Sprintf("reason=%s", key),
		fmt.Sprintf("created=%d", time.Now().Unix()),
	}
	if err := os.WriteFile(warnPath, []byte(strings.Join(payload, "\n")+"\n"), 0644); err != nil {
		h.logf("warn state write failed for %s: %v", rel.Path, err)
		return
	}
	if tag == "" {
		tag = "AUTONUKE"
	}
	if description == "" {
		description = key
	}
	message := fmt.Sprintf("%s: [%s] %s owner=%s warned after %s, nukes after %s",
		tag,
		rel.Section,
		rel.Name,
		h.ownerLabel(rel),
		formatMinutes(warnAfter),
		formatMinutes(nukeAfter),
	)
	if detail != "" {
		message += " [" + detail + "]"
	}
	h.logf(message)
	h.appendHistory("warn", rel, description, detail)
	if h.svc != nil && h.svc.EmitEvent != nil {
		h.svc.EmitEvent(string(core.EventAutonukeWarn), rel.Path, rel.Name, rel.Section, 0, 0, map[string]string{
			"relname":    rel.Name,
			"section":    rel.Section,
			"owner":      h.ownerLabel(rel),
			"rule":       key,
			"tag":        tag,
			"reason":     description,
			"detail":     detail,
			"warn_after": formatMinutes(warnAfter),
			"nuke_after": formatMinutes(nukeAfter),
			"message":    message,
		})
	}
}

func (h *Handler) clearAllWarnings(rel releaseCandidate) {
	h.clearWarning(rel, "empty")
	h.clearWarning(rel, "halfempty")
	h.clearWarning(rel, "incomplete")
	h.clearWarning(rel, "banned")
	h.clearWarning(rel, "allowed")
}

func (h *Handler) clearWarning(rel releaseCandidate, key string) {
	_ = os.Remove(h.warningFile(rel, key))
}

func (h *Handler) warningFile(rel releaseCandidate, key string) string {
	sum := sha1.Sum([]byte(strings.ToLower(rel.Path + "|" + key)))
	return path.Join(h.cfg.StateDir, fmt.Sprintf("prewarned.%s.%x", key, sum[:6]))
}

func (h *Handler) cleanupOldNukes() {
	limitMinutes := h.cfg.DeleteNukes.DeleteAfterMin
	if limitMinutes <= 0 {
		return
	}
	for _, pattern := range h.currentSectionPatterns() {
		base := sectionPatternBase(pattern)
		for _, entry := range h.svc.Bridge.PluginListDir(base) {
			if !entry.IsDir {
				continue
			}
			if !strings.HasPrefix(entry.Name, h.cfg.NukedPrefix) {
				continue
			}
			age := h.nukedAgeMinutes(path.Join(base, entry.Name), entry.ModTime)
			if age < limitMinutes {
				continue
			}
			target := path.Join(base, entry.Name)
			if _, err := h.runSITE("WIPE " + target); err != nil {
				h.logf("delete old nuke failed for %s: %v", target, err)
				h.appendHistory("cleanup_failed", releaseCandidate{
					Path:    target,
					Name:    entry.Name,
					Section: sectionFromPath(base),
					Owner:   entry.Owner,
					ModTime: entry.ModTime,
				}, "delete old nuke failed", err.Error())
				continue
			}
			if err := h.svc.Bridge.DeleteFile(target); err != nil && !isCleanupNotFoundError(err) {
				h.logf("delete old nuke VFS cleanup skipped for %s: %v", target, err)
			}
			h.markNukeDeleted(target)
			h.logf("deleted old nuked release %s after %s", target, formatMinutes(limitMinutes))
			rel := releaseCandidate{
				Path:    target,
				Name:    entry.Name,
				Section: sectionFromPath(base),
				Owner:   entry.Owner,
				ModTime: entry.ModTime,
			}
			reason := fmt.Sprintf("deleted after %s", formatMinutes(limitMinutes))
			h.appendHistory("cleanup_deleted", rel, reason, "")
			h.emitCleanupDeleted(rel, reason)
		}
	}
}

func (h *Handler) markNukeDeleted(target string) {
	db, err := core.GetNukeHistoryDB(false)
	if err != nil || db == nil {
		return
	}
	if _, err := db.MarkDeleted(target); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.logf("mark old nuke deleted failed for %s: %v", target, err)
	}
}

func (h *Handler) emitCleanupDeleted(rel releaseCandidate, reason string) {
	if h == nil || h.svc == nil || h.svc.EmitEvent == nil {
		return
	}
	// The dir on disk uses the configured nuke prefix; announce the original
	// release name, not the nuke folder name.
	relName := displayReleaseName(rel.Name, h.cfg.NukedPrefix)
	message := fmt.Sprintf("deleted old nuked release [%s] %s (%s)", rel.Section, relName, reason)
	h.svc.EmitEvent(string(core.EventAutonukeDelete), rel.Path, relName, rel.Section, 0, 0, map[string]string{
		"relname": relName,
		"section": rel.Section,
		"owner":   h.ownerLabel(rel),
		"reason":  reason,
		"message": message,
	})
}

// displayReleaseName strips the exact configured nuke directory prefix so custom
// styles work without altering legitimate release names that start with brackets.
func displayReleaseName(name, prefix string) string {
	n := strings.TrimSpace(name)
	prefix = strings.TrimSpace(prefix)
	if prefix != "" && strings.HasPrefix(n, prefix) {
		if relName := strings.TrimSpace(strings.TrimPrefix(n, prefix)); relName != "" {
			return relName
		}
	}
	return n
}

func (h *Handler) nukedAgeMinutes(nukedPath string, fallbackModTime int64) int {
	if db, err := core.GetNukeHistoryDB(false); err == nil && db != nil {
		if entry, err := db.FindActiveByPath(nukedPath); err == nil && entry != nil && entry.NukedAt > 0 {
			return int(time.Since(time.Unix(entry.NukedAt, 0)).Minutes())
		}
	}
	if fallbackModTime > 0 {
		return int(time.Since(time.Unix(fallbackModTime, 0)).Minutes())
	}
	return 0
}

func (h *Handler) excludeTokens() []string {
	out := append([]string(nil), h.cfg.Excludes...)
	for _, base := range h.cfg.AffilsDirs {
		for _, entry := range h.svc.Bridge.PluginListDir(base) {
			if entry.IsDir && !containsFold(out, entry.Name) {
				out = append(out, entry.Name)
			}
		}
	}
	return out
}

func (h *Handler) isProtectedBase(dirPath string) bool {
	clean := path.Clean(dirPath)
	for _, pattern := range h.cfg.Sections {
		if sectionProtectedBase(pattern) == clean {
			return true
		}
	}
	return false
}

func (h *Handler) walkVisibleFiles(dirPath string, maxDepth int) []fileInfo {
	if maxDepth < 0 {
		return nil
	}
	out := []fileInfo{}
	for _, entry := range h.svc.Bridge.PluginListDir(dirPath) {
		if strings.HasPrefix(entry.Name, ".") {
			continue
		}
		info := fileInfo{
			Path:      path.Join(dirPath, entry.Name),
			Name:      entry.Name,
			IsDir:     entry.IsDir,
			IsSymlink: entry.IsSymlink,
			Link:      entry.LinkTarget,
			ModTime:   entry.ModTime,
		}
		if entry.IsDir && maxDepth > 0 {
			out = append(out, h.walkVisibleFiles(info.Path, maxDepth-1)...)
			continue
		}
		out = append(out, info)
	}
	return out
}

func (h *Handler) isReleaseIncomplete(dirPath string, jumpOn []string) bool {
	sfv := h.svc.Bridge.GetSFVData(dirPath)
	if len(sfv) > 0 {
		return h.sfvMissingFiles(dirPath, sfv)
	}
	jumpSet := make(map[string]bool, len(jumpOn))
	for _, name := range jumpOn {
		jumpSet[strings.ToLower(strings.TrimSpace(name))] = true
	}
	for _, entry := range h.svc.Bridge.PluginListDir(dirPath) {
		if !entry.IsDir {
			continue
		}
		if !jumpSet[strings.ToLower(entry.Name)] {
			continue
		}
		childPath := path.Join(dirPath, entry.Name)
		childSFV := h.svc.Bridge.GetSFVData(childPath)
		if len(childSFV) == 0 {
			continue
		}
		return h.sfvMissingFiles(childPath, childSFV)
	}
	return false
}

func (h *Handler) sfvMissingFiles(dirPath string, sfv map[string]uint32) bool {
	present := make(map[string]bool)
	for _, file := range h.walkVisibleFiles(dirPath, 3) {
		if file.IsDir {
			continue
		}
		present[strings.ToLower(file.Name)] = true
	}
	for name := range sfv {
		if !present[strings.ToLower(name)] {
			return true
		}
	}
	return false
}

func timedNukeReason(base string, minutes int) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "Autonuke"
	}
	if minutes <= 0 {
		return base
	}
	unit := "minutes"
	if minutes == 1 {
		unit = "minute"
	}
	return fmt.Sprintf("%s after %d %s", base, minutes, unit)
}

func (h *Handler) nuke(rel releaseCandidate, multiplier int, reason string) bool {
	if h.isProtectedBase(rel.Path) || isDatedBucketName(rel.Name) {
		h.logf("refusing to nuke protected path %s [%s] reason=%s", rel.Path, rel.Section, reason)
		h.appendHistory("skip_protected_nuke", rel, reason, "protected base or dated bucket")
		h.clearAllWarnings(rel)
		return false
	}
	siteArgs := fmt.Sprintf("NUKE %s x%d -Auto- %s", rel.Path, multiplier, reason)
	responseLines, err := h.runSITE(siteArgs)
	if err != nil {
		response := responseText(responseLines)
		if response != "" {
			h.logf("nuke failed for %s: %v (%s)", rel.Path, err, response)
			h.appendHistory("nuke_failed", rel, reason, response)
		} else {
			h.logf("nuke failed for %s: %v", rel.Path, err)
			h.appendHistory("nuke_failed", rel, reason, err.Error())
		}
		return false
	}
	h.logf("nuked %s [%s] reason=%s", rel.Path, rel.Section, reason)
	h.appendHistory("nuked", rel, reason, fmt.Sprintf("multiplier=x%d", multiplier))
	return true
}

func (h *Handler) historyFile() string {
	return path.Join(h.cfg.StateDir, "history.jsonl")
}

func (h *Handler) appendHistory(action string, rel releaseCandidate, reason string, detail string) {
	entry := historyEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    strings.TrimSpace(action),
		Path:      strings.TrimSpace(rel.Path),
		Name:      strings.TrimSpace(rel.Name),
		Section:   strings.TrimSpace(rel.Section),
		Owner:     strings.TrimSpace(rel.Owner),
		Reason:    strings.TrimSpace(reason),
		Detail:    strings.TrimSpace(detail),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		h.logf("history marshal failed for %s: %v", rel.Path, err)
		return
	}
	f, err := os.OpenFile(h.historyFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		h.logf("history open failed for %s: %v", rel.Path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		h.logf("history write failed for %s: %v", rel.Path, err)
	}
}

func (h *Handler) ownerLabel(rel releaseCandidate) string {
	if strings.TrimSpace(rel.Owner) != "" {
		return rel.Owner
	}
	return "unknown"
}

func sectionFromPath(p string) string {
	parts := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "DEFAULT"
	}
	if parts[0] == "FOREIGN" && len(parts) > 1 {
		return parts[1]
	}
	return parts[0]
}

func pathHasBase(target, base string) bool {
	target = strings.ToLower(path.Clean(target))
	base = strings.ToLower(sectionPatternBase(base))
	return target == base || strings.HasPrefix(target, base+"/")
}

func firstPatternHit(name string, patterns []string) string {
	nameLower := strings.ToLower(name)
	for _, token := range patterns {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(nameLower, strings.ToLower(token)) {
			return token
		}
	}
	return ""
}

func formatMinutes(mins int) string {
	if mins <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", mins)
}

func visibleEntries(entries []pluginpkg.FileEntry) []pluginpkg.FileEntry {
	out := make([]pluginpkg.FileEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, ".") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (h *Handler) runSITE(siteArgs string) ([]string, error) {
	if h.siteRunner != nil {
		return h.siteRunner(siteArgs)
	}
	addr := net.JoinHostPort(h.cfg.Host, strconv.Itoa(h.cfg.Port))
	timeout := time.Duration(h.cfg.TimeoutSeconds) * time.Second
	rawConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	conn := rawConn
	reader := bufio.NewReader(conn)
	if _, _, err := readFTPResponse(reader); err != nil {
		return nil, err
	}

	if h.cfg.UseTLS {
		if err := writeFTPCommand(conn, "AUTH TLS"); err != nil {
			return nil, err
		}
		code, lines, err := readFTPResponse(reader)
		if err != nil {
			return nil, err
		}
		if code < 200 || code >= 400 {
			clean := responseLines(lines)
			return clean, fmt.Errorf("AUTH TLS failed: %s", responseText(clean))
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: h.cfg.Host, InsecureSkipVerify: h.cfg.Insecure})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		conn = tlsConn
		reader = bufio.NewReader(conn)
	}

	if err := writeFTPCommand(conn, "USER "+h.cfg.User); err != nil {
		return nil, err
	}
	code, lines, err := readFTPResponse(reader)
	if err != nil {
		return nil, err
	}
	if code == 331 {
		if err := writeFTPCommand(conn, "PASS "+h.cfg.Password); err != nil {
			return nil, err
		}
		code, lines, err = readFTPResponse(reader)
		if err != nil {
			return nil, err
		}
	}
	if code < 200 || code >= 300 {
		clean := responseLines(lines)
		return clean, fmt.Errorf("login failed: %s", responseText(clean))
	}

	if err := writeFTPCommand(conn, "SITE "+siteArgs); err != nil {
		return nil, err
	}
	code, lines, err = readFTPResponse(reader)
	if err != nil {
		return nil, err
	}
	_ = writeFTPCommand(conn, "QUIT")
	clean := responseLines(lines)
	if code >= 400 {
		return clean, errors.New(responseText(clean))
	}
	return clean, nil
}

func isCleanupNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such file")
}

func readFTPResponse(r *bufio.Reader) (int, []string, error) {
	line, err := readFTPLine(r)
	if err != nil {
		return 0, nil, err
	}
	if len(line) < 3 {
		return 0, []string{line}, fmt.Errorf("short FTP response: %s", line)
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, []string{line}, err
	}
	lines := []string{line}
	if len(line) > 3 && line[3] == '-' {
		endPrefix := line[:3] + " "
		for {
			next, err := readFTPLine(r)
			if err != nil {
				return code, lines, err
			}
			lines = append(lines, next)
			if strings.HasPrefix(next, endPrefix) {
				break
			}
		}
	}
	return code, lines, nil
}

func readFTPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func writeFTPCommand(conn net.Conn, command string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", command)
	return err
}

func responseText(lines []string) string {
	return strings.Join(lines, " | ")
}

func responseLines(lines []string) []string {
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) >= 4 && isFTPCodePrefix(line) {
			line = strings.TrimSpace(line[4:])
		}
		if line != "" {
			parts = append(parts, line)
		}
	}
	return parts
}

func isFTPCodePrefix(line string) bool {
	if len(line) < 4 {
		return false
	}
	for i := 0; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return false
		}
	}
	return line[3] == ' ' || line[3] == '-'
}

func loadConfig(raw map[string]interface{}) config {
	emptyRaw := subMap(raw, "empty")
	halfRaw := subMap(raw, "half_empty")
	incompleteRaw := subMap(raw, "incomplete")
	bannedRaw := subMap(raw, "banned")
	allowedRaw := subMap(raw, "allowed")
	deleteRaw := subMap(raw, "delete_nukes")
	cfg := config{
		ScanIntervalSeconds: intValue(raw, 600, "scan_interval_seconds", "SLEEPTIME"),
		Host:                stringValue(raw, "127.0.0.1", "host"),
		Port:                intValue(raw, 21212, "port"),
		User:                stringValue(raw, "NUKEBOT", "user", "NUKEUSER", "nuke_user"),
		Password:            stringValue(raw, "change-me", "password", "nuke_password"),
		UseTLS:              boolValue(raw, true, "tls"),
		Insecure:            boolValue(raw, true, "insecure_skip_verify"),
		TimeoutSeconds:      intValue(raw, 10, "timeout_seconds"),
		StateDir:            stringValue(raw, "logs/autonuke", "state_dir", "TEMPDIR"),
		NukedPrefix:         stringValue(raw, "[NUKED]-", "nuked_prefix"),
		CheckCompleteDir:    boolValue(raw, true, "check_complete_dir", "CHECK_COMPLETE_DIR"),
		UserExclude:         stringValue(raw, "weaveftpd", "user_exclude", "USEREXCLUDE"),
	}

	cfg.Sections = normalizeSectionPatterns(stringSliceValue(raw, "sections"))
	cfg.AffilsDirs = normalizeBasePaths(stringSliceValue(raw, "affils_dirs", "AFFILSDIRS"))
	cfg.Excludes = stringSliceValue(raw, "exclude_name_contains", "excludes", "EXCLUDES")
	cfg.ApprovalMarkers = stringSliceValue(raw, "approval_markers")
	if len(cfg.ApprovalMarkers) == 0 {
		cfg.ApprovalMarkers = []string{stringValue(raw, "[Approved_by_", "allowed_marker", "ALLOWED"), ".approved", ".allow"}
	}

	cfg.Empty = timedRule{
		Enabled:         boolValue(emptyRaw, boolValue(raw, true, "totally_empty", "TOTALLYEMPTY"), "enabled"),
		WarnEnabled:     boolValue(emptyRaw, boolValue(raw, true, "pre_nuke_empty", "PRENUKEEMPTY"), "warn_enabled"),
		WarnAfterMin:    intValue(emptyRaw, intValue(raw, 60, "early_empty", "EARLYEMPTY"), "warn_after_min"),
		NukeAfterMin:    intValue(emptyRaw, intValue(raw, 240, "time_empty", "TIMEEMPTY"), "nuke_after_min"),
		Multiplier:      intValue(emptyRaw, intValue(raw, 10, "empty_multiplier", "EMPTYMULTIPLIER"), "multiplier"),
		Reason:          stringValue(emptyRaw, "Empty", "reason"),
		WarnTag:         "ANUKEEMPTY",
		WarnDescription: "empty release",
	}
	cfg.HalfEmpty = timedPayloadRule{
		timedRule: timedRule{
			Enabled:         boolValue(halfRaw, boolValue(raw, true, "half_empty", "HALFEMPTY"), "enabled"),
			WarnEnabled:     boolValue(halfRaw, boolValue(raw, true, "pre_nuke_half_empty", "PRENUKEHALFEMPTY"), "warn_enabled"),
			WarnAfterMin:    intValue(halfRaw, intValue(raw, 60, "early_half_empty", "EARLYHALFEMPTY"), "warn_after_min"),
			NukeAfterMin:    intValue(halfRaw, intValue(raw, 240, "time_half_empty", "TIMEHALFEMPTY"), "nuke_after_min"),
			Multiplier:      intValue(halfRaw, intValue(raw, 10, "half_empty_multiplier", "HALFEMPTYMULTIPLIER"), "multiplier"),
			Reason:          stringValue(halfRaw, "Half-Empty", "reason"),
			WarnTag:         "ANUKEHEMPTY",
			WarnDescription: "half-empty release",
		},
		PayloadExtensions: normalizeExtensions(coalesceStringSlice(stringSliceValue(halfRaw, "payload_extensions"), stringSliceValue(raw, "payload_extensions", "EMPTYEXCLUDE"))),
	}
	cfg.Incomplete = incompleteRule{
		timedRule: timedRule{
			Enabled:         boolValue(incompleteRaw, boolValue(raw, true, "incomplete", "INCOMPLETE"), "enabled"),
			WarnEnabled:     boolValue(incompleteRaw, boolValue(raw, true, "pre_nuke_incomplete", "PRENUKEINCOM"), "warn_enabled"),
			WarnAfterMin:    intValue(incompleteRaw, intValue(raw, 60, "early_incomplete", "EARLYINCOM"), "warn_after_min"),
			NukeAfterMin:    intValue(incompleteRaw, intValue(raw, 240, "time_incomplete", "TIMEINCOM"), "nuke_after_min"),
			Multiplier:      intValue(incompleteRaw, intValue(raw, 10, "incomplete_multiplier", "INCOMMULTIPLIER"), "multiplier"),
			Reason:          stringValue(incompleteRaw, "Incomplete", "reason"),
			WarnTag:         "ANUKEINC",
			WarnDescription: "incomplete release",
		},
		JumpOn: coalesceStringSlice(stringSliceValue(incompleteRaw, "jump_on"), stringSliceValue(raw, "jump_on", "JUMPON")),
	}
	cfg.Banned = timedPatternRules{
		Enabled:         boolValue(bannedRaw, boolValue(raw, false, "banned_words", "BANNEDWORDS"), "enabled"),
		WarnEnabled:     boolValue(bannedRaw, boolValue(raw, true, "ban_pre_nuke", "BANPRENUKE"), "warn_enabled"),
		WarnAfterMin:    intValue(bannedRaw, intValue(raw, 1, "early_ban_warn", "EARLYBANPRENUKE"), "warn_after_min"),
		NukeAfterMin:    intValue(bannedRaw, intValue(raw, 1, "time_ban_nuke", "TIMEBANNUKE"), "nuke_after_min"),
		DefaultMulti:    intValue(bannedRaw, intValue(raw, 10, "ban_multiplier", "BANMULTIPLIER"), "default_multiplier"),
		WarnTag:         "ANUKEBAN",
		WarnDescription: "banned release",
		Rules:           patternRulesValue(bannedRaw, "rules"),
	}
	if len(cfg.Banned.Rules) == 0 {
		cfg.Banned.Rules = parseLegacyPatternRules(stringSliceValue(raw, "ban_dirs", "BANDIRS"), cfg.Banned.DefaultMulti)
	}
	cfg.Allowed = timedPatternRules{
		Enabled:         boolValue(allowedRaw, boolValue(raw, false, "allowed_words", "ALLOWEDWORDS"), "enabled"),
		WarnEnabled:     boolValue(allowedRaw, boolValue(raw, true, "allow_pre_nuke", "ALLOWPRENUKE"), "warn_enabled"),
		WarnAfterMin:    intValue(allowedRaw, intValue(raw, 1, "early_allow_warn", "EARLYALLOWPRENUKE"), "warn_after_min"),
		NukeAfterMin:    intValue(allowedRaw, intValue(raw, 20, "time_allow_nuke", "TIMEALLOWNUKE"), "nuke_after_min"),
		DefaultMulti:    intValue(allowedRaw, intValue(raw, 3, "allow_multiplier", "ALLOWMULTIPLIER"), "default_multiplier"),
		WarnTag:         "ANUKEALLOW",
		WarnDescription: "not-allowed release",
		Rules:           patternRulesValue(allowedRaw, "rules"),
	}
	if len(cfg.Allowed.Rules) == 0 {
		cfg.Allowed.Rules = parseLegacyPatternRules(stringSliceValue(raw, "allow_dirs", "ALLOWDIRS"), cfg.Allowed.DefaultMulti)
	}
	cfg.DeleteNukes = deleteRule{
		Enabled:        boolValue(deleteRaw, boolValue(raw, true, "delete_nukes", "DELETENUKES"), "enabled"),
		DeleteAfterMin: intValue(deleteRaw, intValue(raw, 180, "time_to_delete_minutes", "TIMETODELEM"), "delete_after_min"),
	}
	return cfg
}

func normalizeSectionPatterns(values []string) []string {
	out := make([]string, 0, len(values))
	for _, item := range values {
		item = normalizeVirtualPath(item)
		if item == "" {
			continue
		}
		if strings.ContainsAny(item, "*?[]") {
			out = append(out, path.Clean(item))
			continue
		}
		out = append(out, path.Clean(item+"/*"))
	}
	return dedupeStrings(out)
}

func sectionPatternBase(pattern string) string {
	pattern = path.Clean(strings.TrimSpace(expandDateTokens(pattern)))
	pattern = strings.TrimSuffix(pattern, "/*/*")
	pattern = strings.TrimSuffix(pattern, "/*")
	if pattern == "" {
		return "/"
	}
	return path.Clean(pattern)
}

func sectionProtectedBase(pattern string) string {
	pattern = path.Clean(strings.TrimSpace(normalizeVirtualPath(pattern)))
	pattern = strings.TrimSuffix(pattern, "/*/*")
	pattern = strings.TrimSuffix(pattern, "/*")
	if pattern == "" || pattern == "/" {
		return "/"
	}
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	for len(parts) > 0 && isDateTokenSegment(parts[len(parts)-1]) {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func isDateTokenSegment(part string) bool {
	part = strings.TrimSpace(strings.ToUpper(part))
	if part == "" {
		return false
	}
	if strings.Contains(part, "{TODAY}") || strings.Contains(part, "{YESTERDAY}") {
		return true
	}
	return strings.Contains(part, "MM") ||
		strings.Contains(part, "DD") ||
		strings.Contains(part, "YYYY") ||
		strings.Contains(part, "YY") ||
		strings.Contains(part, "WW")
}

func normalizeBasePaths(values []string) []string {
	out := make([]string, 0, len(values))
	for _, item := range values {
		item = expandDateTokens(normalizeVirtualPath(item))
		if item != "" {
			out = append(out, path.Clean(item))
		}
	}
	return dedupeStrings(out)
}

func normalizeVirtualPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for _, prefix := range []string{"/glftpd/site", "glftpd/site", "/site", "site"} {
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(prefix)) {
			p = p[len(prefix):]
			break
		}
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

func (h *Handler) currentSectionPatterns() []string {
	out := make([]string, 0, len(h.cfg.Sections))
	for _, item := range h.cfg.Sections {
		item = expandDateTokens(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		out = append(out, path.Clean(item))
	}
	return dedupeStrings(out)
}

func expandDateTokens(v string) string {
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	_, isoWeek := now.ISOWeek()
	v = strings.ReplaceAll(v, "YYYY", fmt.Sprintf("%04d", now.Year()))
	v = strings.ReplaceAll(v, "YY", fmt.Sprintf("%02d", now.Year()%100))
	v = strings.ReplaceAll(v, "MM", now.Format("01"))
	v = strings.ReplaceAll(v, "DD", now.Format("02"))
	v = strings.ReplaceAll(v, "WW", fmt.Sprintf("%02d", isoWeek))
	v = strings.ReplaceAll(v, "{today}", now.Format("0102"))
	v = strings.ReplaceAll(v, "{yesterday}", yesterday.Format("0102"))
	return v
}

func normalizeExtensions(values []string) []string {
	out := make([]string, 0, len(values))
	for _, item := range values {
		item = strings.TrimSpace(strings.ToLower(item))
		item = strings.TrimPrefix(item, ".")
		if item != "" {
			out = append(out, item)
		}
	}
	return dedupeStrings(out)
}

func parseLegacyPatternRules(values []string, defaultMulti int) []patternRule {
	out := []patternRule{}
	for _, item := range values {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			continue
		}
		rule := patternRule{BasePath: normalizeVirtualPath(parts[0]), Multiplier: defaultMulti}
		for _, rawPattern := range strings.Split(parts[1], ";") {
			rawPattern = strings.TrimSpace(rawPattern)
			if rawPattern == "" {
				continue
			}
			multi := defaultMulti
			pattern := rawPattern
			if strings.Contains(rawPattern, "*") {
				p := strings.SplitN(rawPattern, "*", 2)
				pattern = strings.TrimSpace(p[0])
				if n, err := strconv.Atoi(strings.TrimSpace(p[1])); err == nil && n > 0 {
					multi = n
				}
			}
			rule.Patterns = append(rule.Patterns, pattern)
			rule.Multiplier = multi
		}
		if len(rule.Patterns) > 0 {
			out = append(out, rule)
		}
	}
	return out
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func coalesceStringSlice(values ...[]string) []string {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}

func subMap(raw map[string]interface{}, key string) map[string]interface{} {
	if raw == nil {
		return nil
	}
	if v, ok := raw[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func patternRulesValue(raw map[string]interface{}, key string) []patternRule {
	if raw == nil {
		return nil
	}
	items, ok := raw[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]patternRule, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		rule := patternRule{
			BasePath:    sectionPatternBase(stringValue(entry, "", "path", "base_path")),
			Patterns:    stringSliceValue(entry, "patterns"),
			Multiplier:  intValue(entry, 0, "multiplier"),
			Description: stringValue(entry, "", "description"),
		}
		if rule.BasePath == "" || len(rule.Patterns) == 0 {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func stringValue(raw map[string]interface{}, fallback string, keys ...string) string {
	for _, key := range keys {
		if v, ok := raw[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return fallback
}

func stringSliceValue(raw map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		switch vals := raw[key].(type) {
		case []string:
			return append([]string(nil), vals...)
		case []interface{}:
			out := make([]string, 0, len(vals))
			for _, item := range vals {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
			return out
		}
	}
	return nil
}

func intValue(raw map[string]interface{}, fallback int, keys ...string) int {
	for _, key := range keys {
		switch v := raw[key].(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return fallback
}

func boolValue(raw map[string]interface{}, fallback bool, keys ...string) bool {
	for _, key := range keys {
		switch v := raw[key].(type) {
		case bool:
			return v
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "yes", "1", "on":
				return true
			case "false", "no", "0", "off":
				return false
			}
		}
	}
	return fallback
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func (r patternRule) MultiplierOr(defaultValue int) int {
	if r.Multiplier > 0 {
		return r.Multiplier
	}
	return defaultValue
}

func (h *Handler) logf(format string, args ...interface{}) {
	if h.svc != nil && h.svc.Logger != nil {
		h.svc.Logger.Printf("[AUTONUKE] "+format, args...)
		return
	}
	log.Printf("[AUTONUKE] "+format, args...)
}

var (
	datedBucketMMDD       = regexp.MustCompile(`^\d{4}$`)
	datedBucketYYYYMMDD   = regexp.MustCompile(`^\d{8}$`)
	datedBucketYYYY_MM_DD = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	datedBucketWW_YYYY    = regexp.MustCompile(`^\d{2}-\d{4}$`)
	datedBucketYYYY_WW    = regexp.MustCompile(`^\d{4}-\d{2}$`)
)

func isDatedBucketName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	return datedBucketMMDD.MatchString(name) ||
		datedBucketYYYYMMDD.MatchString(name) ||
		datedBucketYYYY_MM_DD.MatchString(name) ||
		datedBucketWW_YYYY.MatchString(name) ||
		datedBucketYYYY_WW.MatchString(name)
}
