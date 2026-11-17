package slowkick

import (
	"fmt"
	"log"
	"path"
	"strings"
	"sync"
	"time"

	"weaveftpd/internal/plugin"
	"weaveftpd/internal/user"
)

const slowkickMonitorInterval = time.Second

type Handler struct {
	uploadWindow          time.Duration
	banScope              string
	samples               map[string][]speedSample
	releaseBans           map[releaseBanKey]time.Time
	svc                   *plugin.Services
	enabled               bool
	monitorUploads        bool
	monitorDownloads      bool
	uploadGrace           time.Duration
	downloadGrace         time.Duration
	minUploadSpeedBytes   float64
	minDownloadSpeedBytes float64
	minUsersOnline        int
	excludeUsers          map[string]struct{}
	excludeGroups         map[string]struct{}
	excludePaths          []string
	excludeExtensions     map[string]struct{}
	announceKick          bool
	tempbanAfterKick      bool
	tempbanDuration       time.Duration
	debug                 bool
	configMu              sync.RWMutex
	stopOnce              sync.Once
	stopCh                chan struct{}
	mu                    sync.Mutex
	tempBans              map[string]time.Time
	kickedTransfers       map[string]struct{}
}

type configSnapshot struct {
	uploadWindow          time.Duration
	banScope              string
	enabled               bool
	monitorUploads        bool
	monitorDownloads      bool
	uploadGrace           time.Duration
	downloadGrace         time.Duration
	minUploadSpeedBytes   float64
	minDownloadSpeedBytes float64
	minUsersOnline        int
	excludeUsers          map[string]struct{}
	excludeGroups         map[string]struct{}
	excludePaths          []string
	excludeExtensions     map[string]struct{}
	announceKick          bool
	tempbanAfterKick      bool
	tempbanDuration       time.Duration
}

func New() *Handler {
	return &Handler{
		enabled:               true,
		monitorUploads:        true,
		monitorDownloads:      true,
		uploadGrace:           5 * time.Second,
		downloadGrace:         5 * time.Second,
		minUploadSpeedBytes:   25 * 1024,
		minDownloadSpeedBytes: 50 * 1024,
		minUsersOnline:        2,
		excludeUsers:          map[string]struct{}{},
		excludeGroups:         map[string]struct{}{},
		excludePaths:          normalizePaths([]string{"/PRE", "/REQUESTS", "/SPEEDTEST"}),
		excludeExtensions:     lowerSet([]string{"sfv"}),
		stopCh:                make(chan struct{}),
		tempBans:              map[string]time.Time{},
		kickedTransfers:       map[string]struct{}{},
	}
}

func (h *Handler) Name() string { return "slowkick" }

func (h *Handler) Init(svc *plugin.Services, cfg map[string]interface{}) error {
	h.svc = svc
	if err := h.applyConfig(cfg, true); err != nil {
		return err
	}
	go h.monitorLoop()
	return nil
}

func (h *Handler) ReloadConfig(cfg map[string]interface{}) error {
	return h.applyConfig(cfg, false)
}

func (h *Handler) applyConfig(cfg map[string]interface{}, initial bool) error {
	uploadWindow := durationSecondsConfig(cfg, "upload_window_seconds", 0)
	banScope, _ := cfg["ban_scope"].(string)
	banScope = strings.ToLower(strings.TrimSpace(banScope))
	if banScope == "" {
		banScope = "site"
	}
	if uploadWindow < 0 || uploadWindow > 5*time.Minute {
		return fmt.Errorf("upload_window_seconds must be between 0 and 300")
	}
	if banScope != "site" && banScope != "release" {
		return fmt.Errorf("ban_scope must be site or release")
	}
	enabled := boolConfig(cfg, "enabled", true)
	monitorUploads := boolConfig(cfg, "monitor_uploads", true)
	monitorDownloads := boolConfig(cfg, "monitor_downloads", true)
	uploadGrace := durationSecondsConfig(cfg, "verify_upload_seconds", 5)
	downloadGrace := durationSecondsConfig(cfg, "verify_download_seconds", 5)
	minUploadSpeedBytes := float64(intConfig(cfg["min_upload_speed_kbps"], 25) * 1024)
	minDownloadSpeedBytes := float64(intConfig(cfg["min_download_speed_kbps"], 50) * 1024)
	minUsersOnline := intConfig(cfg["min_users_online"], 2)
	excludeUsers := lowerSet(stringSliceConfig(cfg["exclude_users"]))
	excludeGroups := lowerSet(stringSliceConfig(cfg["exclude_groups"]))
	excludePaths := normalizePaths([]string{"/PRE", "/REQUESTS", "/SPEEDTEST"})
	if raw, ok := cfg["exclude_paths"]; ok {
		excludePaths = normalizePaths(stringSliceConfig(raw))
	}
	excludeExtensions := lowerSet([]string{"sfv"})
	if raw, ok := cfg["exclude_extensions"]; ok {
		excludeExtensions = lowerSet(normalizeExtensions(stringSliceConfig(raw)))
	}
	announceKick := boolConfig(cfg, "announce_kick", true)
	tempbanAfterKick := boolConfig(cfg, "tempban_after_kick", true)
	tempbanDuration := durationSecondsConfig(cfg, "tempban_seconds", 15)
	debug := boolConfig(cfg, "debug", h.svc != nil && h.svc.Debug)

	h.configMu.Lock()
	h.uploadWindow = uploadWindow
	h.banScope = banScope
	h.enabled = enabled
	h.monitorUploads = monitorUploads
	h.monitorDownloads = monitorDownloads
	h.uploadGrace = uploadGrace
	h.downloadGrace = downloadGrace
	h.minUploadSpeedBytes = minUploadSpeedBytes
	h.minDownloadSpeedBytes = minDownloadSpeedBytes
	h.minUsersOnline = minUsersOnline
	h.excludeUsers = excludeUsers
	h.excludeGroups = excludeGroups
	h.excludePaths = excludePaths
	h.excludeExtensions = excludeExtensions
	h.announceKick = announceKick
	h.tempbanAfterKick = tempbanAfterKick
	h.tempbanDuration = tempbanDuration
	h.debug = debug
	h.configMu.Unlock()
	h.mu.Lock()
	h.samples = nil
	h.mu.Unlock()

	action := "reloaded"
	if initial {
		action = "initialized"
	}
	h.logf(
		"%s enabled=%v uploads=%v downloads=%v up_min=%.1fKB/s down_min=%.1fKB/s min_users=%d tempban=%v tempban_seconds=%d upload_window_seconds=%d ban_scope=%s",
		action,
		enabled,
		monitorUploads,
		monitorDownloads,
		minUploadSpeedBytes/1024.0,
		minDownloadSpeedBytes/1024.0,
		minUsersOnline,
		tempbanAfterKick,
		int(tempbanDuration/time.Second),
		int(uploadWindow/time.Second),
		banScope,
	)
	return nil
}

func (h *Handler) snapshotConfig() configSnapshot {
	h.configMu.RLock()
	defer h.configMu.RUnlock()
	return configSnapshot{
		uploadWindow:          h.uploadWindow,
		banScope:              h.banScope,
		enabled:               h.enabled,
		monitorUploads:        h.monitorUploads,
		monitorDownloads:      h.monitorDownloads,
		uploadGrace:           h.uploadGrace,
		downloadGrace:         h.downloadGrace,
		minUploadSpeedBytes:   h.minUploadSpeedBytes,
		minDownloadSpeedBytes: h.minDownloadSpeedBytes,
		minUsersOnline:        h.minUsersOnline,
		excludeUsers:          h.excludeUsers,
		excludeGroups:         h.excludeGroups,
		excludePaths:          h.excludePaths,
		excludeExtensions:     h.excludeExtensions,
		announceKick:          h.announceKick,
		tempbanAfterKick:      h.tempbanAfterKick,
		tempbanDuration:       h.tempbanDuration,
	}
}

func (h *Handler) OnEvent(evt *plugin.Event) error { return nil }

func (h *Handler) ValidateLogin(u *user.User, remoteIP string) error {
	cfg := h.snapshotConfig()
	if u == nil || !cfg.enabled || cfg.banScope == "release" || !cfg.tempbanAfterKick || cfg.tempbanDuration <= 0 {
		return nil
	}
	if _, excluded := cfg.excludeUsers[strings.ToLower(strings.TrimSpace(u.Name))]; excluded {
		return nil
	}
	if _, excluded := cfg.excludeGroups[strings.ToLower(strings.TrimSpace(u.PrimaryGroup))]; excluded {
		return nil
	}
	if until, ok := h.activeTempBan(u.Name, time.Now()); ok {
		remaining := int(time.Until(until).Seconds())
		if remaining < 1 {
			remaining = 1
		}
		return fmt.Errorf("temporarily banned after slow transfer, retry in %ds", remaining)
	}
	return nil
}

func (h *Handler) HandleSlowTransfer(username, primaryGroup, transferPath, direction, slaveName string, transferIndex int32, actualSpeedBytes, minSpeedBytes int64) {
	h.handleSlowTransfer(plugin.ActiveSession{
		User:              username,
		PrimaryGroup:      primaryGroup,
		TransferDirection: direction,
		TransferPath:      transferPath,
		TransferSlaveName: slaveName,
		TransferSlaveIdx:  transferIndex,
	}, actualSpeedBytes, minSpeedBytes)
}

func (h *Handler) handleSlowTransfer(snap plugin.ActiveSession, actualSpeedBytes, minSpeedBytes int64) {
	now := time.Now()
	h.pruneExpiredTempBans(now)
	cfg := h.snapshotConfig()
	if !h.shouldApplyTransferPolicyWithConfig(cfg, snap.User, snap.PrimaryGroup, snap.TransferPath, snap.TransferDirection) {
		return
	}
	policy := transferPolicy{
		direction:     strings.ToLower(strings.TrimSpace(snap.TransferDirection)),
		minSpeedBytes: float64(minSpeedBytes),
	}
	switch policy.direction {
	case "upload":
		policy.kickEvent = "SLOWUPLOADKICK"
	case "download":
		policy.kickEvent = "SLOWDOWNLOADKICK"
	default:
		return
	}
	h.recordSlowTransferKick(cfg, snap, actualSpeedBytes, policy)
}

func (h *Handler) recordSlowTransferKick(cfg configSnapshot, snap plugin.ActiveSession, actualSpeedBytes int64, policy transferPolicy) {
	if cfg.tempbanAfterKick && cfg.tempbanDuration > 0 && cfg.banScope != "release" {
		h.setTempBan(snap.User, time.Now().Add(cfg.tempbanDuration))
	}
	if cfg.announceKick {
		h.emitSlowEvent(policy.kickEvent, snap, float64(actualSpeedBytes), policy)
	}
	action := "kicked"
	if cfg.banScope == "release" && policy.direction == "upload" {
		action = "aborted upload for"
	}
	h.logf("%s %s for slow %s in %s at %.1fKB/s", action, snap.User, policy.direction, snap.TransferPath, float64(actualSpeedBytes)/1024.0)
}

func (h *Handler) Stop() error {
	h.stopOnce.Do(func() {
		if h.stopCh != nil {
			close(h.stopCh)
		}
	})
	return nil
}

func (h *Handler) monitorLoop() {
	ticker := time.NewTicker(slowkickMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.checkActiveTransfers(time.Now())
		case <-h.stopCh:
			return
		}
	}
}

type liveTransferKey struct {
	slave string
	index int32
}

func (h *Handler) checkActiveTransfers(now time.Time) {
	if h == nil || h.svc == nil || h.svc.ListActiveSessions == nil {
		return
	}
	cfg := h.snapshotConfig()
	sessions := h.svc.ListActiveSessions()
	liveStats := h.liveStatsByTransfer()
	activeKeys := make(map[string]struct{}, len(sessions))

	for _, snap := range sessions {
		key := slowKickTransferKey(snap)
		if key != "" {
			activeKeys[key] = struct{}{}
		}
		policy, grace, ok := h.policyForSnapshot(cfg, snap)
		if !ok {
			continue
		}
		started := snap.TransferStartedAt
		if strings.TrimSpace(snap.TransferSlaveName) != "" && snap.TransferSlaveIdx != 0 {
			stat, found := liveStats[liveTransferKey{
				slave: strings.ToLower(strings.TrimSpace(snap.TransferSlaveName)),
				index: snap.TransferSlaveIdx,
			}]
			if !found || !sameTransferPath(stat.Path, snap.TransferPath) {
				h.clearSamples(key)
				continue
			}
			// Slave timing excludes connect/TLS setup and starts at the first byte.
			started = stat.StartedAt
		}
		if started.IsZero() {
			h.clearSamples(key)
			continue
		}
		speed, ok := transferSpeedBytes(snap, liveStats, now)
		if policy.direction == "upload" && cfg.uploadWindow > 0 {
			bytes := snap.TransferBytes
			windowStart := time.Time{}
			if stat, found := liveStats[liveTransferKey{strings.ToLower(strings.TrimSpace(snap.TransferSlaveName)), snap.TransferSlaveIdx}]; found {
				bytes = stat.Transferred
				windowStart = stat.StartedAt
			} else if bytes == 0 {
				h.clearSamples(key)
				continue
			}
			speed, ok = h.windowSpeed(key, windowStart, now, bytes, cfg.uploadWindow)
		}
		if now.Sub(started) < grace {
			continue
		}
		if !ok {
			continue
		}
		if speed >= policy.minSpeedBytes {
			continue
		}
		h.kickSlowTransfer(cfg, snap, speed, policy)
	}

	h.pruneKickedTransfers(activeKeys)
	h.pruneExpiredTempBans(now)
}

func (h *Handler) liveStatsByTransfer() map[liveTransferKey]plugin.LiveTransferStat {
	if h == nil || h.svc == nil || h.svc.GetLiveTransferStats == nil {
		return nil
	}
	stats := h.svc.GetLiveTransferStats()
	out := make(map[liveTransferKey]plugin.LiveTransferStat, len(stats))
	for _, stat := range stats {
		key := liveTransferKey{
			slave: strings.ToLower(strings.TrimSpace(stat.SlaveName)),
			index: stat.TransferIndex,
		}
		if key.slave == "" || key.index == 0 {
			continue
		}
		out[key] = stat
	}
	return out
}

func (h *Handler) policyForSnapshot(cfg configSnapshot, snap plugin.ActiveSession) (transferPolicy, time.Duration, bool) {
	if !snap.LoggedIn || !h.shouldApplyTransferPolicyWithConfig(cfg, snap.User, snap.PrimaryGroup, snap.TransferPath, snap.TransferDirection) {
		return transferPolicy{}, 0, false
	}
	switch strings.ToLower(strings.TrimSpace(snap.TransferDirection)) {
	case "upload":
		if cfg.minUploadSpeedBytes <= 0 {
			return transferPolicy{}, 0, false
		}
		return transferPolicy{
			direction:     "upload",
			minSpeedBytes: cfg.minUploadSpeedBytes,
			kickEvent:     "SLOWUPLOADKICK",
		}, cfg.uploadGrace, true
	case "download":
		if cfg.minDownloadSpeedBytes <= 0 {
			return transferPolicy{}, 0, false
		}
		return transferPolicy{
			direction:     "download",
			minSpeedBytes: cfg.minDownloadSpeedBytes,
			kickEvent:     "SLOWDOWNLOADKICK",
		}, cfg.downloadGrace, true
	default:
		return transferPolicy{}, 0, false
	}
}

func transferSpeedBytes(snap plugin.ActiveSession, liveStats map[liveTransferKey]plugin.LiveTransferStat, now time.Time) (float64, bool) {
	if stat, ok := liveStats[liveTransferKey{
		slave: strings.ToLower(strings.TrimSpace(snap.TransferSlaveName)),
		index: snap.TransferSlaveIdx,
	}]; ok && sameTransferPath(stat.Path, snap.TransferPath) {
		if stat.SpeedBytes > 0 {
			return stat.SpeedBytes, true
		}
		if !stat.StartedAt.IsZero() && now.After(stat.StartedAt) {
			return float64(stat.Transferred) / now.Sub(stat.StartedAt).Seconds(), true
		}
		return 0, true
	}
	if strings.TrimSpace(snap.TransferSlaveName) != "" && snap.TransferSlaveIdx != 0 {
		return 0, false
	}
	if snap.TransferStartedAt.IsZero() || !now.After(snap.TransferStartedAt) {
		return 0, false
	}
	return float64(snap.TransferBytes) / now.Sub(snap.TransferStartedAt).Seconds(), true
}

func sameTransferPath(a, b string) bool {
	a = strings.ToLower(path.Clean("/" + strings.TrimSpace(a)))
	b = strings.ToLower(path.Clean("/" + strings.TrimSpace(b)))
	return a == b
}

func (h *Handler) kickSlowTransfer(cfg configSnapshot, snap plugin.ActiveSession, speed float64, policy transferPolicy) {
	key := slowKickTransferKey(snap)
	if key == "" || !h.markKickedTransfer(key) {
		return
	}

	reason := fmt.Sprintf("slowkick: %.0fB/s below %.0fB/s", speed, policy.minSpeedBytes)
	stopped := false
	if cfg.banScope == "release" && policy.direction == "upload" {
		root := h.releaseRoot(snap.TransferPath)
		if root == "" || h.svc == nil || h.svc.AbortSessionTransfer == nil {
			h.forgetKickedTransfer(key)
			return
		}
		// Install before aborting so another session cannot immediately reclaim
		// this release while the transfer handler is unwinding.
		banKey := releaseBanKey{strings.ToLower(strings.TrimSpace(snap.User)), root}
		until := time.Now().Add(cfg.tempbanDuration)
		var previous time.Time
		if cfg.tempbanAfterKick && cfg.tempbanDuration > 0 {
			h.mu.Lock()
			if h.releaseBans == nil {
				h.releaseBans = make(map[releaseBanKey]time.Time)
			}
			previous = h.releaseBans[banKey]
			if previous.After(until) {
				until = previous
			}
			h.releaseBans[banKey] = until
			h.mu.Unlock()
		}
		stopped = h.svc.AbortSessionTransfer(snap, reason)
		if !stopped {
			h.mu.Lock()
			if h.releaseBans[banKey] == until {
				if previous.IsZero() {
					delete(h.releaseBans, banKey)
				} else {
					h.releaseBans[banKey] = previous
				}
			}
			h.mu.Unlock()
			h.forgetKickedTransfer(key)
			return
		}
		h.recordSlowTransferKick(cfg, snap, int64(speed), policy)
		return
	}
	if h.svc != nil {
		// Disconnecting the FTP session also aborts its attached slave or local
		// data connection. An abort without the disconnect leaves the user logged
		// in and able to claim another slot immediately, which is not a kick.
		if h.svc.DisconnectSession != nil && snap.ID != 0 {
			stopped = h.svc.DisconnectSession(snap.ID)
		}
		if !stopped && h.svc.AbortTransfer != nil && strings.TrimSpace(snap.TransferSlaveName) != "" && snap.TransferSlaveIdx != 0 {
			stopped = h.svc.AbortTransfer(snap.TransferSlaveName, snap.TransferSlaveIdx, reason)
		}
	}
	if !stopped {
		h.forgetKickedTransfer(key)
		h.logf("unable to abort slow %s for %s in %s", policy.direction, snap.User, snap.TransferPath)
		return
	}

	h.recordSlowTransferKick(cfg, snap, int64(speed), policy)
}

func slowKickTransferKey(snap plugin.ActiveSession) string {
	if snap.ID == 0 || strings.TrimSpace(snap.TransferPath) == "" || strings.TrimSpace(snap.TransferDirection) == "" || snap.TransferStartedAt.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d|%s|%s|%d|%s|%d",
		snap.ID,
		strings.ToLower(strings.TrimSpace(snap.TransferDirection)),
		strings.ToLower(path.Clean("/"+strings.TrimSpace(snap.TransferPath))),
		snap.TransferStartedAt.UnixNano(),
		strings.ToLower(strings.TrimSpace(snap.TransferSlaveName)),
		snap.TransferSlaveIdx,
	)
}

func (h *Handler) markKickedTransfer(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.kickedTransfers == nil {
		h.kickedTransfers = map[string]struct{}{}
	}
	if _, ok := h.kickedTransfers[key]; ok {
		return false
	}
	h.kickedTransfers[key] = struct{}{}
	return true
}

func (h *Handler) forgetKickedTransfer(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.kickedTransfers, key)
}

func (h *Handler) pruneKickedTransfers(active map[string]struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key := range h.kickedTransfers {
		if _, ok := active[key]; !ok {
			delete(h.kickedTransfers, key)
		}
	}
	for key := range h.samples {
		if _, ok := active[key]; !ok {
			delete(h.samples, key)
		}
	}
}

func (h *Handler) shouldApplyTransferPolicyWithConfig(cfg configSnapshot, username, primaryGroup, transferPath, direction string) bool {
	if !cfg.enabled {
		return false
	}
	if strings.TrimSpace(username) == "" || strings.TrimSpace(transferPath) == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "upload":
		if !cfg.monitorUploads {
			return false
		}
	case "download":
		if !cfg.monitorDownloads {
			return false
		}
	default:
		return false
	}
	if _, excluded := cfg.excludeUsers[strings.ToLower(strings.TrimSpace(username))]; excluded {
		return false
	}
	if _, excluded := cfg.excludeGroups[strings.ToLower(strings.TrimSpace(primaryGroup))]; excluded {
		return false
	}
	if cfg.minUsersOnline > 0 && h.svc != nil && h.svc.ListActiveSessions != nil {
		loggedIn := 0
		for _, snap := range h.svc.ListActiveSessions() {
			if snap.LoggedIn && strings.TrimSpace(snap.User) != "" {
				loggedIn++
			}
		}
		if loggedIn < cfg.minUsersOnline {
			return false
		}
	}
	cleanPath := strings.ToLower(path.Clean("/" + strings.TrimSpace(transferPath)))
	for _, prefix := range cfg.excludePaths {
		if cleanPath == prefix || strings.HasPrefix(cleanPath, prefix+"/") {
			return false
		}
	}
	ext := strings.TrimPrefix(strings.ToLower(path.Ext(strings.TrimSpace(transferPath))), ".")
	if ext != "" {
		if _, excluded := cfg.excludeExtensions[ext]; excluded {
			return false
		}
	}
	return true
}

type transferPolicy struct {
	direction     string
	minSpeedBytes float64
	kickEvent     string
}

func (h *Handler) setTempBan(username string, until time.Time) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tempBans[username] = until
}

func (h *Handler) activeTempBan(username string, now time.Time) (time.Time, bool) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return time.Time{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	until, ok := h.tempBans[username]
	if !ok {
		return time.Time{}, false
	}
	if !until.After(now) {
		delete(h.tempBans, username)
		return time.Time{}, false
	}
	return until, true
}

func (h *Handler) pruneExpiredTempBans(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for username, until := range h.tempBans {
		if !until.After(now) {
			delete(h.tempBans, username)
		}
	}
	for key, until := range h.releaseBans {
		if !until.After(now) {
			delete(h.releaseBans, key)
		}
	}
}

func (h *Handler) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if h.svc != nil && h.svc.Logger != nil {
		h.svc.Logger.Printf("[SLOWKICK] %s", msg)
		return
	}
	log.Printf("[SLOWKICK] %s", msg)
}

func (h *Handler) emitSlowEvent(eventType string, snap plugin.ActiveSession, speed float64, policy transferPolicy) {
	if h.svc == nil || h.svc.EmitEvent == nil {
		return
	}
	cfg := h.snapshotConfig()
	data := map[string]string{
		"ban_scope":        cfg.banScope,
		"username":         strings.TrimSpace(snap.User),
		"group":            strings.TrimSpace(snap.PrimaryGroup),
		"direction":        policy.direction,
		"speed_kbps":       fmt.Sprintf("%.2f", speed/1024.0),
		"min_speed_kbps":   fmt.Sprintf("%.2f", policy.minSpeedBytes/1024.0),
		"min_users_online": fmt.Sprintf("%d", cfg.minUsersOnline),
		"slave_name":       strings.TrimSpace(snap.TransferSlaveName),
		"transfer_index":   fmt.Sprintf("%d", snap.TransferSlaveIdx),
		"session_id":       fmt.Sprintf("%d", snap.ID),
	}
	if cfg.tempbanAfterKick && cfg.tempbanDuration > 0 && strings.Contains(eventType, "KICK") {
		data["tempban_seconds"] = fmt.Sprintf("%d", int(cfg.tempbanDuration/time.Second))
	}
	h.svc.EmitEvent(eventType, snap.TransferPath, path.Base(strings.TrimSpace(snap.TransferPath)), "", 0, speed/(1024.0*1024.0), data)
}

func boolConfig(cfg map[string]interface{}, key string, fallback bool) bool {
	if raw, ok := cfg[key].(bool); ok {
		return raw
	}
	return fallback
}

func intConfig(raw interface{}, fallback int) int {
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return fallback
	}
}

func durationSecondsConfig(cfg map[string]interface{}, key string, fallback int) time.Duration {
	return time.Duration(intConfig(cfg[key], fallback)) * time.Second
}

func stringSliceConfig(raw interface{}) []string {
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func lowerSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func normalizePaths(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(path.Clean("/" + strings.TrimSpace(value)))
		if value == "" || value == "." {
			continue
		}
		out = append(out, value)
	}
	return out
}

func normalizeExtensions(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		value = strings.TrimPrefix(value, ".")
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
