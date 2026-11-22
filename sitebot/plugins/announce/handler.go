package announce

import (
	"fmt"
	"log"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"weaveftpd/sitebot/internal/event"
	"weaveftpd/sitebot/internal/plugin"
	tmpl "weaveftpd/sitebot/internal/template"
)

type releaseState struct {
	FirstUser       string
	Users           map[string]bool
	HasSFV          bool
	FirstRar        bool
	Created         bool
	Completed       bool
	HalfwayDone     bool
	CurrentLeader   string
	AnnouncedLeader map[string]bool
	StatsLines      []string
	LastSeen        time.Time
}

type pendingPretime struct {
	section string
	relpath string
	vars    map[string]string
	timer   *time.Timer
}

type AnnouncePlugin struct {
	debug               bool
	theme               *tmpl.Theme
	slowUploadWarnChans []string
	slowUploadKickChans []string
	slowDnWarnChans     []string
	slowDnKickChans     []string
	pretimeMode         string
	pretimeInlineWait   time.Duration
	loginFailCooldown   time.Duration
	asyncEmit           func(outType, text, section, relpath string)
	mu                  sync.Mutex
	state               map[string]*releaseState
	completedReleases   map[string]time.Time
	pendingPretime      map[string]*pendingPretime
	lastLoginFail       map[string]time.Time
}

func New() *AnnouncePlugin {
	return &AnnouncePlugin{
		state:             map[string]*releaseState{},
		pretimeMode:       "newline",
		pretimeInlineWait: 1500 * time.Millisecond,
		loginFailCooldown: 10 * time.Second,
		pendingPretime:    map[string]*pendingPretime{},
		completedReleases: map[string]time.Time{},
		lastLoginFail:     map[string]time.Time{},
	}
}
func (p *AnnouncePlugin) Name() string { return "Announce" }
func (p *AnnouncePlugin) Initialize(config map[string]interface{}) error {
	if debug, ok := config["debug"].(bool); ok {
		p.debug = debug
	}
	if secs, ok := config["loginfail_cooldown_seconds"]; ok {
		if v := configInt(secs, 10); v > 0 {
			p.loginFailCooldown = time.Duration(v) * time.Second
		}
	}
	p.slowUploadWarnChans = p.routeTargets(config, "SLOWUPLOADWARN", "SLOWKICK", "SLAVEAUTH", "LOGIN")
	p.slowUploadKickChans = p.routeTargets(config, "SLOWUPLOADKICK", "SLOWKICK", "SLAVEAUTH", "LOGIN")
	p.slowDnWarnChans = p.routeTargets(config, "SLOWDOWNLOADWARN", "SLOWKICK", "SLAVEAUTH", "LOGIN")
	p.slowDnKickChans = p.routeTargets(config, "SLOWDOWNLOADKICK", "SLOWKICK", "SLAVEAUTH", "LOGIN")
	pretimeCfg := plugin.ConfigSection(config, "pretime")
	if mode, ok := pretimeCfg["mode"].(string); ok && strings.TrimSpace(mode) != "" {
		p.pretimeMode = strings.ToLower(strings.TrimSpace(mode))
	}
	if themeFile, ok := config["theme_file"].(string); ok && strings.TrimSpace(themeFile) != "" {
		th, err := tmpl.LoadTheme(themeFile)
		if err == nil {
			p.theme = th
			if p.debug {
				log.Printf("[Announce] loaded theme %s (%d templates, %d vars)", themeFile, len(th.Announces), len(th.Vars))
			}
		} else {
			log.Printf("[Announce] theme load failed for %s: %v", themeFile, err)
		}
	}
	return nil
}
func (p *AnnouncePlugin) Close() error { return nil }

func (p *AnnouncePlugin) SetAsyncEmitter(fn func(outType, text, section, relpath string)) {
	p.asyncEmit = fn
}

func (p *AnnouncePlugin) routeTargets(config map[string]interface{}, routeKeys ...string) []string {
	for _, key := range routeKeys {
		switch routes := config["type_routes"].(type) {
		case map[string]interface{}:
			if raw, ok := routes[key]; ok {
				if out := plugin.ToStringSlice(raw, nil); len(out) > 0 {
					return out
				}
			}
		case map[string][]string:
			if raw, ok := routes[key]; ok {
				if out := plugin.ToStringSlice(raw, nil); len(out) > 0 {
					return out
				}
			}
		}
	}
	if raw, ok := config["default_channel"].(string); ok {
		if channel := strings.TrimSpace(raw); channel != "" {
			return []string{channel}
		}
	}
	return nil
}

func (p *AnnouncePlugin) appendTargeted(outs []plugin.Output, outType, text string, targets []string) []plugin.Output {
	if len(targets) == 0 {
		return append(outs, plugin.Output{Type: outType, Text: text})
	}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		outs = append(outs, plugin.Output{Type: outType, Target: target, Text: text})
	}
	return outs
}

func resetRaceOutputState(st *releaseState) {
	if st == nil {
		return
	}
	st.Completed = false
	st.HalfwayDone = false
	st.CurrentLeader = ""
	st.AnnouncedLeader = nil
	st.StatsLines = nil
}

func appendRaceStatsLine(st *releaseState, line string) {
	if st == nil {
		return
	}
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}
	if strings.TrimSpace(line) == "" && line != "\u00a0" {
		return
	}
	st.StatsLines = append(st.StatsLines, line)
}

func flushRaceStats(st *releaseState) string {
	if st == nil || len(st.StatsLines) == 0 {
		return ""
	}
	lines := append([]string(nil), st.StatsLines...)
	st.StatsLines = nil
	return strings.Join(lines, "\n")
}

func raceStateReady(st *releaseState, vars map[string]string) bool {
	if st != nil && st.HasSFV {
		return true
	}
	if vars == nil {
		return false
	}
	return strings.TrimSpace(vars["t_files"]) != ""
}

func releaseName(evt *event.Event) string {
	for _, key := range []string{"release_name", "relname"} {
		if rel := strings.TrimSpace(evt.Data[key]); rel != "" && rel != "." && rel != "/" {
			return rel
		}
	}
	if evt.Path == "" {
		return evt.Filename
	}
	clean := path.Clean(evt.Path)
	base := path.Base(clean)
	// For directory-scoped events, Path IS the release directory itself.
	if evt.Type == event.EventMKDir || evt.Type == event.EventRMDir || evt.Type == event.EventRaceEnd ||
		evt.Type == event.EventMediaInfo || evt.Type == event.EventAudioInfo ||
		evt.Type == event.EventPre || evt.Type == event.EventPreBW ||
		evt.Type == event.EventPreBWUser || evt.Type == event.EventPreBWInterval {
		return base
	}
	if evt.Type == event.EventNuke || evt.Type == event.EventUnnuke {
		return base
	}
	if evt.Type == event.EventAutonukeWarn || evt.Type == event.EventAutonukeDelete {
		return base
	}
	name := strings.ToLower(evt.Filename)
	if strings.Contains(name, ".") {
		releaseDir := path.Base(path.Dir(clean))
		if strings.EqualFold(evt.Section, "REQUESTS") && isDirectRequestWrapperPath(path.Dir(clean)) {
			return stripRequestWrapperPrefix(releaseDir)
		}
		return releaseDir
	}
	return base
}

func normalizeReleaseDisplayName(evt *event.Event, current string) string {
	current = strings.TrimSpace(current)
	if current != "" && current != "." && current != "/" {
		return current
	}
	if evt == nil {
		return current
	}
	if evt.Path != "" {
		clean := path.Clean("/" + strings.TrimSpace(evt.Path))
		if clean != "/" && clean != "." {
			if evt.Type == event.EventUpload || evt.Type == event.EventDownload {
				if parent := strings.TrimSpace(path.Base(path.Dir(clean))); parent != "" && parent != "." && parent != "/" {
					return parent
				}
			}
			if base := strings.TrimSpace(path.Base(clean)); base != "" && base != "." && base != "/" {
				return base
			}
		}
	}
	if name := strings.TrimSpace(evt.Filename); name != "" && name != "." && name != "/" {
		return name
	}
	return current
}

func releaseStateKey(evt *event.Event) string {
	rel := releaseName(evt)
	if subdir := strings.TrimSpace(evt.Data["release_subdir"]); subdir != "" {
		return rel + "|" + subdir
	}
	return rel
}

func classifyFile(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.HasSuffix(l, ".sfv"):
		return "sfv"
	case strings.HasSuffix(l, ".nfo"):
		return "nfo"
	case strings.Contains(l, "/sample/") || strings.Contains(l, ".sample."):
		return "sample"
	case isAudioFile(l):
		return "audio"
	case isZipFile(l):
		return "zip"
	case regexpRAR(l):
		return "rar"
	default:
		return "other"
	}
}
func isAudioFile(name string) bool {
	return strings.HasSuffix(name, ".mp3") || strings.HasSuffix(name, ".flac") || strings.HasSuffix(name, ".m4a") || strings.HasSuffix(name, ".wav")
}
func regexpRAR(name string) bool {
	if strings.HasSuffix(name, ".rar") {
		return true
	}
	idx := strings.LastIndexByte(name, '.')
	if idx < 0 || idx+4 != len(name) {
		return false
	}
	ext := name[idx+1:]
	return len(ext) == 3 && ext[0] >= 'r' && ext[0] <= 'z' && ext[1] >= '0' && ext[1] <= '9' && ext[2] >= '0' && ext[2] <= '9'
}
func isZipFile(name string) bool {
	return strings.HasSuffix(name, ".zip")
}
func speedMB(evt *event.Event) string { return formatSpeed(evt.Speed * 1024 * 1024) }
func mb(size int64) string            { return fmt.Sprintf("%.0fMB", float64(size)/1024.0/1024.0) }

func (p *AnnouncePlugin) vars(evt *event.Event) map[string]string {
	rel := normalizeReleaseDisplayName(evt, releaseName(evt))
	v := map[string]string{
		"section":     evt.Section,
		"relname":     rel,
		"reldir":      rel,
		"u_name":      evt.User,
		"g_name":      evt.Group,
		"user":        evt.User,
		"group":       evt.Group,
		"filename":    evt.Filename,
		"file":        evt.Filename,
		"path":        evt.Path,
		"u_speed":     speedMB(evt),
		"speed":       speedMB(evt),
		"file_mbytes": mb(evt.Size),
		"size":        mb(evt.Size),
	}
	for k, val := range evt.Data {
		v[k] = val
	}
	for key, value := range v {
		if strings.Contains(key, "speed") {
			v[key] = scaleSpeed(value)
		}
	}
	v["relname"] = normalizeReleaseDisplayName(evt, v["relname"])
	if strings.TrimSpace(v["reldir"]) == "" || strings.TrimSpace(v["reldir"]) == "." || strings.TrimSpace(v["reldir"]) == "/" {
		v["reldir"] = v["relname"]
	}
	if subdir := strings.TrimSpace(evt.Data["release_subdir"]); subdir != "" {
		v["release_subdir"] = subdir
		v["subdir_prefix"] = "[" + subdir + "] "
	} else {
		v["release_subdir"] = ""
		v["subdir_prefix"] = ""
	}
	if v["t_file_label"] == "" {
		v["t_file_label"] = "file(s)"
	}
	if v["subtitle_format"] == "" {
		v["subtitle_format"] = "None"
	}
	p.addSectionPalette(v, v["section"])
	if v["user"] == "" {
		v["user"] = v["u_name"]
	}
	if v["group"] == "" {
		v["group"] = v["g_name"]
	}
	if v["file"] == "" {
		v["file"] = v["filename"]
	}
	if v["speed"] == "" {
		v["speed"] = v["u_speed"]
	}
	if v["t_mbytes"] != "" {
		v["size"] = v["t_mbytes"]
	} else if v["size"] == "" {
		v["size"] = v["file_mbytes"]
	}
	if v["files"] == "" {
		if v["t_files"] != "" {
			v["files"] = v["t_files"]
		} else if v["t_filecount"] != "" {
			v["files"] = v["t_filecount"]
		}
	}
	if v["racers"] == "" && v["u_count"] != "" {
		v["racers"] = v["u_count"]
	}
	if v["leaduser"] == "" && v["leader_name"] != "" {
		v["leaduser"] = v["leader_name"]
	}
	if v["leadsize"] == "" && v["leader_mb"] != "" {
		v["leadsize"] = v["leader_mb"] + "MB"
	}
	if v["leadfiles"] == "" {
		v["leadfiles"] = v["leader_files"]
	}
	if v["leadpercent"] == "" && v["leader_pct"] != "" {
		v["leadpercent"] = v["leader_pct"] + "%"
	}
	if v["leadspeed"] == "" {
		v["leadspeed"] = v["leader_speed"]
	}
	if v["filesleft"] == "" {
		v["filesleft"] = v["t_filesleft"]
	}
	return v
}

func (p *AnnouncePlugin) addSectionPalette(vars map[string]string, section string) {
	for i := 1; i <= 5; i++ {
		key := fmt.Sprintf("sec_c%d", i)
		vars[key] = p.sectionColor(section, i)
	}
	vars["section_colored"] = "\x03" + vars["sec_c2"] + section + "\x03"
	vars["sectioncolor"] = vars["sec_c2"]
}

func (p *AnnouncePlugin) sectionColor(section string, slot int) string {
	fallback := "02"
	if p.theme != nil {
		keys := []string{
			fmt.Sprintf("COLOR_%s_%d", strings.ToUpper(section), slot),
			fmt.Sprintf("section_color.%s.%d", section, slot),
			fmt.Sprintf("section_color.%s.%d", strings.ToUpper(section), slot),
			fmt.Sprintf("COLOR_DEFAULT_%d", slot),
			fmt.Sprintf("section_color.default.%d", slot),
			"section_color." + section,
			"section_color." + strings.ToUpper(section),
			"section_color.default",
		}
		for _, key := range keys {
			if c := strings.TrimSpace(p.theme.Vars[key]); c != "" {
				return strings.TrimLeft(c, "cC")
			}
		}
	}
	return fallback
}

func (p *AnnouncePlugin) render(key string, vars map[string]string, fallback string) string {
	if p.theme != nil {
		if raw, ok := p.theme.Announces[key]; ok && raw != "" {
			return tmpl.Render(raw, vars)
		}
	}
	return fallback
}

func (p *AnnouncePlugin) shouldInlinePretime() bool {
	return strings.EqualFold(strings.TrimSpace(p.pretimeMode), "inline")
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func pretimeKey(relpath string) string {
	return strings.ToLower(path.Clean("/" + strings.TrimSpace(relpath)))
}

func syntheticNewRelPath(evt *event.Event, section string) string {
	if evt == nil {
		return ""
	}
	if evt.Type == event.EventMKDir {
		return path.Clean("/" + strings.TrimSpace(evt.Path))
	}
	return ""
}

func (p *AnnouncePlugin) renderNewLine(section, rel string, vars map[string]string) string {
	return p.render("NEWDIR", vars, fmt.Sprintf("NEW : [%s] %s%s by %s", section, vars["subdir_prefix"], rel, vars["u_name"]))
}

func (p *AnnouncePlugin) renderInlinePretime(evt *event.Event, section, rel string, vars map[string]string) string {
	key := "NEWPRETIMEINLINE"
	fallback := fmt.Sprintf("NEW : [%s] %s by %s :: released %s ago", section, rel, vars["u_name"], vars["preage"])
	if evt != nil && evt.Type == event.EventOldPreTime {
		key = "OLDPRETIMEINLINE"
	}
	return p.render(key, vars, fallback)
}

func (p *AnnouncePlugin) queueInlinePretime(relpath, section string, vars map[string]string) {
	if p.asyncEmit == nil || relpath == "" {
		return
	}
	key := pretimeKey(relpath)
	if existing := p.pendingPretime[key]; existing != nil {
		if existing.timer != nil {
			existing.timer.Stop()
		}
		delete(p.pendingPretime, key)
	}
	pending := &pendingPretime{
		section: section,
		relpath: relpath,
		vars:    cloneStringMap(vars),
	}
	pending.timer = time.AfterFunc(p.pretimeInlineWait, func() {
		p.flushInlinePretimeFallback(key)
	})
	p.pendingPretime[key] = pending
}

func (p *AnnouncePlugin) flushInlinePretimeFallback(key string) {
	var pending *pendingPretime
	p.mu.Lock()
	pending = p.pendingPretime[key]
	if pending != nil {
		delete(p.pendingPretime, key)
	}
	p.mu.Unlock()
	if pending == nil || p.asyncEmit == nil {
		return
	}
	rel := pending.vars["relname"]
	text := p.renderNewLine(pending.section, rel, pending.vars)
	p.asyncEmit("NEW", text, pending.section, pending.relpath)
}

func (p *AnnouncePlugin) emitInlinePretime(evt *event.Event, section, rel string, vars map[string]string) bool {
	key := pretimeKey(evt.Path)
	pending := p.pendingPretime[key]
	if pending == nil {
		return false
	}
	if pending.timer != nil {
		pending.timer.Stop()
	}
	delete(p.pendingPretime, key)
	if p.asyncEmit == nil {
		return false
	}
	mergedVars := cloneStringMap(pending.vars)
	for k, v := range vars {
		mergedVars[k] = v
	}
	text := p.renderInlinePretime(evt, section, rel, mergedVars)
	go p.asyncEmit("NEW", text, section, pending.relpath)
	return true
}

func shouldSuppressLateReleaseInfo(st *releaseState) bool {
	return st != nil && st.Completed
}

func shouldSuppressLatePretime(st *releaseState) bool {
	return shouldSuppressLateReleaseInfo(st)
}

func completedReleaseKeyByPath(relpath string) string {
	return "path:" + strings.ToLower(path.Clean("/"+strings.TrimSpace(relpath)))
}

func completedReleaseKeyBySectionRel(section, rel string) string {
	return "name:" + strings.ToLower(strings.TrimSpace(section)) + "|" + strings.ToLower(strings.TrimSpace(rel))
}

func (p *AnnouncePlugin) markReleaseCompleted(section, rel, relpath string) {
	now := time.Now()
	if relpath = strings.TrimSpace(relpath); relpath != "" {
		p.completedReleases[completedReleaseKeyByPath(relpath)] = now
	}
	if rel = strings.TrimSpace(rel); rel != "" {
		p.completedReleases[completedReleaseKeyBySectionRel(section, rel)] = now
	}
	if len(p.completedReleases) > 2000 {
		cutoff := now.Add(-24 * time.Hour)
		for key, seenAt := range p.completedReleases {
			if seenAt.Before(cutoff) {
				delete(p.completedReleases, key)
			}
		}
	}
}

func (p *AnnouncePlugin) clearCompletedRelease(section, rel, relpath string) {
	if relpath = strings.TrimSpace(relpath); relpath != "" {
		delete(p.completedReleases, completedReleaseKeyByPath(relpath))
	}
	if rel = strings.TrimSpace(rel); rel != "" {
		delete(p.completedReleases, completedReleaseKeyBySectionRel(section, rel))
	}
}

func (p *AnnouncePlugin) isReleaseCompleted(section, rel, relpath string) bool {
	if relpath = strings.TrimSpace(relpath); relpath != "" {
		if _, ok := p.completedReleases[completedReleaseKeyByPath(relpath)]; ok {
			return true
		}
	}
	if rel = strings.TrimSpace(rel); rel != "" {
		if _, ok := p.completedReleases[completedReleaseKeyBySectionRel(section, rel)]; ok {
			return true
		}
	}
	return false
}

func loginFailKey(vars map[string]string) string {
	username := strings.ToLower(strings.TrimSpace(vars["username"]))
	reason := strings.ToLower(strings.TrimSpace(vars["reason"]))
	ip := strings.ToLower(strings.TrimSpace(vars["remote_ip"]))
	mask := strings.ToLower(strings.TrimSpace(vars["remote_mask"]))
	return username + "|" + reason + "|" + ip + "|" + mask
}

func loginStorageDetail(vars map[string]string) string {
	action := cleanLoginStorageText(vars["action"])
	errText := cleanLoginStorageText(vars["error"])
	if len(errText) > 180 {
		errText = errText[:177] + "..."
	}
	switch {
	case action != "" && errText != "":
		return fmt.Sprintf(" during %s: %s", action, errText)
	case action != "":
		return " during " + action
	case errText != "":
		return ": " + errText
	default:
		return " while updating daemon state"
	}
}

func cleanLoginStorageText(text string) string {
	text = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\r", " "), "\n", " "))
	return strings.Join(strings.Fields(text), " ")
}

func colorizeNukees(raw string) string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		open := strings.LastIndex(part, " (")
		close := strings.LastIndex(part, ")")
		if open > 0 && close == len(part)-1 && close > open+2 {
			user := strings.TrimSpace(part[:open])
			size := strings.TrimSpace(part[open+2 : close])
			if user != "" && size != "" {
				out = append(out, "\x0306"+user+"\x03 \x0301("+size+")\x03")
				continue
			}
		}
		out = append(out, "\x0306"+part+"\x03")
	}
	return strings.Join(out, "\x0301, \x03")
}

func friendlyAutonukeLabel(tag, reason string) string {
	switch strings.ToUpper(strings.TrimSpace(tag)) {
	case "ANUKEINC":
		return "AUTONUKE INCOMPLETE"
	case "ANUKEEMPTY":
		return "AUTONUKE EMPTY"
	case "ANUKEHALF":
		return "AUTONUKE HALF-EMPTY"
	case "ANUKEBAN":
		return "AUTONUKE BANNED"
	}
	if reason = strings.TrimSpace(reason); reason != "" {
		return "AUTONUKE " + strings.ToUpper(reason)
	}
	return "AUTONUKE"
}

func humanizeAutonukeMessage(message, tag, reason string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	rawTag := strings.TrimSpace(tag)
	if rawTag == "" {
		return message
	}
	prefix := rawTag + ":"
	if !strings.HasPrefix(message, prefix) {
		return message
	}
	return friendlyAutonukeLabel(tag, reason) + ":" + strings.TrimPrefix(message, prefix)
}

func configInt(raw interface{}, fallback int) int {
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

func (p *AnnouncePlugin) OnEvent(evt *event.Event) ([]plugin.Output, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rel := releaseName(evt)
	if rel == "." || rel == "/" || rel == "" {
		rel = evt.Filename
	}
	stateKey := releaseStateKey(evt)
	st := p.state[stateKey]
	if st == nil {
		st = &releaseState{Users: map[string]bool{}, LastSeen: time.Now()}
		p.state[stateKey] = st
	}
	st.LastSeen = time.Now()
	vars := p.vars(evt)
	section := vars["section"]
	if section == "" {
		section = "DEFAULT"
		vars["section"] = section
	}
	fileType := classifyFile(strings.ToLower(evt.Path))
	outs := []plugin.Output{}
	skipReleaseAnnounce := strings.EqualFold(strings.TrimSpace(evt.Data["skip_release_announce"]), "true")

	switch evt.Type {
	case event.EventNewDay:
		fallback := fmt.Sprintf("NEW DAY: -%s- A new day has come! %s has been created along with its symlink.", section, vars["date"])
		if vars["symlink"] != "true" {
			fallback = fmt.Sprintf("NEW DAY: -%s- A new day has come! %s has been created.", section, vars["date"])
		}
		outs = append(outs, plugin.Output{Type: "NEWDAY", Text: p.render("NEWDAY", vars, fallback)})
	case event.EventAudioInfo:
		fallback := fmt.Sprintf("AUDIO-INFO: [%s] %s %s.",
			section, rel, formatAudioInfoSummary(vars))
		outs = append(outs, plugin.Output{Type: "AUDIOINFO", Text: p.render("AUDIOINFO", vars, fallback)})
	case event.EventMediaInfo:
		if isSectionRootMetadataEvent(evt, section) {
			return nil, nil
		}
		if shouldSuppressLateReleaseInfo(st) || p.isReleaseCompleted(section, rel, evt.Path) {
			return nil, nil
		}
		fallback := fmt.Sprintf("SAMPLE-INFO: [%s] %s - Video: %s - Audio: %s - Subs: %s - Duration: %s",
			section, rel, formatSampleVideoLabel(vars), formatSampleAudioLabel(vars), formatSampleSubtitleLabel(vars), formatSampleDurationLabel(vars))
		outs = append(outs, plugin.Output{Type: "MEDIAINFO", Text: p.render("MEDIAINFO", vars, fallback)})
	case event.EventCustom:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			message = fmt.Sprintf("CUSTOM: [%s] %s", section, rel)
		}
		outType := strings.ToUpper(strings.TrimSpace(vars["announce_type"]))
		if outType == "" {
			outType = "CUSTOM"
		}
		templateKey := strings.ToUpper(strings.TrimSpace(vars["template"]))
		if templateKey == "" {
			templateKey = outType
		}
		outs = append(outs, plugin.Output{Type: outType, Text: p.render(templateKey, vars, p.render("CUSTOM", vars, message))})
	case event.EventSpeedtest:
		nick := vars["nick"]
		if nick == "" {
			nick = evt.User
		}
		action := vars["action"]
		if action == "" {
			action = "transferred"
		}
		sizeMB := vars["size_mb"]
		if sizeMB == "" {
			sizeMB = strings.TrimSuffix(mb(evt.Size), "MB")
		}
		speed := vars["speed_mbs"]
		if speed == "" {
			speed = speedMB(evt)
		}
		fallback := fmt.Sprintf("SPEEDTEST: %s %s a %sMB file with %s", nick, action, sizeMB, speed)
		outs = append(outs, plugin.Output{Type: "SPEEDTEST", Text: p.render("SPEEDTEST", vars, fallback)})
	case event.EventMKDir:
		if skipReleaseAnnounce {
			return nil, nil
		}
		if isReleaseDir(evt.Path, section) {
			if !st.Created {
				resetRaceOutputState(st)
				p.clearCompletedRelease(section, rel, evt.Path)
				st.Created = true
				if p.shouldInlinePretime() && p.asyncEmit != nil {
					p.queueInlinePretime(syntheticNewRelPath(evt, section), section, vars)
				} else {
					outs = append(outs, plugin.Output{Type: "NEW", Text: p.renderNewLine(section, rel, vars)})
				}
			}
		}
	case event.EventUpload:
		if skipReleaseAnnounce {
			return nil, nil
		}
		if isRequestRaceUploadPath(evt.Path, section) && !st.Created {
			st.Created = true
			outs = append(outs, plugin.Output{Type: "NEW", Text: p.renderNewLine(section, rel, vars)})
		}
		switch fileType {
		case "nfo", "sample":
			return nil, nil
		case "sfv":
			if st.Completed {
				return nil, nil
			}
			if !st.HasSFV {
				st.HasSFV = true
				outs = append(outs, plugin.Output{Type: "RACE", Text: p.render("SFV_RAR", vars, fmt.Sprintf("RACE: [%s] Got SFV for %s%s uploaded by %s.", section, vars["subdir_prefix"], rel, evt.User))})
			}
		case "rar", "audio", "zip":
			if st.Completed {
				return nil, nil
			}
			trackedRace := raceStateReady(st, vars)
			if !trackedRace {
				return nil, nil
			}
			if evt.User != "" && !st.Users[evt.User] {
				if !st.FirstRar {
					st.Users[evt.User] = true
					st.FirstRar = true
					key := "UPDATE_RAR"
					fallback := fmt.Sprintf("RACE: [%s] %s%s got its first rar file from %s at %s.", section, vars["subdir_prefix"], rel, evt.User, speedMB(evt))
					if fileType == "audio" {
						key = "UPDATE_TRACK"
						fallback = fmt.Sprintf("RACE: [%s] %s%s got first track from %s at %s.", section, vars["subdir_prefix"], rel, evt.User, speedMB(evt))
					} else if fileType == "zip" {
						key = "UPDATE_ZIP"
						fallback = fmt.Sprintf("RACE: [%s] %s%s got its first zip file from %s at %s.", section, vars["subdir_prefix"], rel, evt.User, speedMB(evt))
					}
					if strings.TrimSpace(vars["t_mbytes"]) == "" {
						key = "UPDATE_RAR_UNKNOWN"
						if fileType == "audio" {
							key = "UPDATE_TRACK"
						} else if fileType == "zip" {
							key = "UPDATE_ZIP_UNKNOWN"
						}
					} else if fileType == "zip" && strings.TrimSpace(vars["t_files"]) == "" {
						key = "UPDATE_ZIP_UNKNOWN"
					}
					outs = append(outs, plugin.Output{Type: "RACE", Text: p.render(key, vars, fallback)})
				} else {
					st.Users[evt.User] = true
					joinVars := map[string]string{}
					for k, v := range vars {
						joinVars[k] = v
					}
					joinSpeed := strings.TrimSpace(joinVars["u_race_speed"])
					if joinSpeed == "" {
						joinSpeed = speedMB(evt)
					}
					joinVars["u_speed"] = joinSpeed
					outs = append(outs, plugin.Output{Type: "RACE", Text: p.render("RACE_RAR", joinVars, fmt.Sprintf("RACE: [%s] %s%s - %s joined the race at %s.", section, vars["subdir_prefix"], rel, evt.User, joinSpeed))})
				}
			}
			// NEW LEADER: announce when the leading user changes. Skip single-racer
			// races (len(st.Users) <= 1), never announce the first leader (no prior
			// leader to overtake), and announce each distinct leader AT MOST ONCE per
			// release -- otherwise close parallel racing makes the byte-based leader
			// flip-flop and re-announces "X takes the lead" on nearly every file.
			if leader := vars["leader_name"]; leader != "" && leader != st.CurrentLeader && len(st.Users) > 1 {
				if st.CurrentLeader != "" && !st.AnnouncedLeader[leader] {
					if st.AnnouncedLeader == nil {
						st.AnnouncedLeader = map[string]bool{}
					}
					st.AnnouncedLeader[leader] = true
					leftText := strings.TrimSpace(vars["t_filesleft"])
					if leftText != "" {
						leftText = " - " + leftText + " files left."
					}
					outs = append(outs, plugin.Output{Type: "RACE", Text: p.render("NEWLEADER", vars, fmt.Sprintf("NEW LEADER: [%s] %s%s - %s takes the lead - %sMB/%sF/%s%%/%s%s", section, vars["subdir_prefix"], rel, leader, vars["leader_mb"], vars["leader_files"], vars["leader_pct"], vars["leader_speed"], leftText))})
				}
				st.CurrentLeader = leader
			}
			// HALFWAY: announce when race passes 50% of file count
			if !st.HalfwayDone {
				if present, total := vars["t_present"], vars["t_files"]; present != "" && total != "" {
					var p1, t1 int
					fmt.Sscanf(present, "%d", &p1)
					fmt.Sscanf(total, "%d", &t1)
					if t1 > 0 && p1*2 >= t1 && p1 < t1 {
						st.HalfwayDone = true
						left := t1 - p1
						if vars["t_filesleft"] == "" {
							vars["t_filesleft"] = fmt.Sprintf("%d", left)
						}
						if vars["t_timeleft"] == "" {
							vars["t_timeleft"] = "N/A"
						}
						if vars["t_avgspeed"] == "" {
							vars["t_avgspeed"] = "0.00MB/s"
						}
						outs = append(outs, plugin.Output{Type: "RACE", Text: p.render("HALFWAY", vars, fmt.Sprintf("HALFWAY: [%s] %s%s - leader: %s [%sMB/%sF/%s%%/%s] - %d files left.", section, vars["subdir_prefix"], rel, vars["leader_name"], vars["leader_mb"], vars["leader_files"], vars["leader_pct"], vars["leader_speed"], left))})
					}
				}
			}
		}
	case event.EventRaceEnd:
		if skipReleaseAnnounce {
			return nil, nil
		}
		st.Completed = true
		st.HalfwayDone = true
		p.markReleaseCompleted(section, rel, evt.Path)
		outs = append(outs, plugin.Output{Type: "COMPLETE", Text: p.render("COMPLETE", vars, fmt.Sprintf("COMPLETE: [%s] %s%s by %s racers - %s/%s/%s/%s", section, vars["subdir_prefix"], rel, vars["u_count"], vars["t_mbytes"], vars["t_files"], vars["t_avgspeed"], vars["t_duration"]))})
	case event.EventRaceStats:
		if skipReleaseAnnounce {
			return nil, nil
		}
		if line := strings.TrimSpace(p.render("STATS_HOF", vars, "STATS: Users Hall Of Fame")); line != "" {
			appendRaceStatsLine(st, line)
		}
		if line := strings.TrimSpace(p.render("STATS_SPEEDS", vars, fmt.Sprintf("STATS: Slowest: %s at %s - Fastest: %s at %s.", vars["u_slowest_name"], vars["u_slowest_speed"], vars["u_fastest_name"], vars["u_fastest_speed"]))); line != "" {
			appendRaceStatsLine(st, line)
		}
		if line := strings.TrimSpace(p.render("STATS_USER_HEADER", vars, "UserTop")); line != "" {
			appendRaceStatsLine(st, line)
		}
	case event.EventRaceUser:
		if skipReleaseAnnounce {
			return nil, nil
		}
		perVars := map[string]string{}
		for k, v := range vars {
			perVars[k] = v
		}
		perVars["u_name"] = vars["u_racer_name"]
		perVars["u_group"] = vars["u_racer_group"]
		perVars["u_files"] = vars["u_racer_files"]
		perVars["u_mb"] = vars["u_racer_mb"]
		perVars["u_pct"] = vars["u_racer_pct"]
		perVars["u_speed"] = vars["u_racer_speed"]
		perVars["u_alup"] = vars["u_alup"]
		perVars["u_wkup"] = vars["u_wkup"]
		perVars["u_monthup"] = vars["u_monthup"]
		perVars["u_dayup"] = vars["u_dayup"]
		perVars["u_aldn"] = vars["u_aldn"]
		perVars["u_wkdn"] = vars["u_wkdn"]
		perVars["u_monthdn"] = vars["u_monthdn"]
		perVars["u_daydn"] = vars["u_daydn"]
		fallback := fmt.Sprintf("%s. %s@%s [%sMB/%s Files/%s%%/%s] [ALLUP #%s][WKUP #%s]",
			vars["u_rank"], perVars["u_name"], perVars["u_group"], perVars["u_mb"], perVars["u_files"], perVars["u_pct"], perVars["u_speed"], perVars["u_alup"], perVars["u_wkup"])
		if line := strings.TrimSpace(p.render("STATS_USER", perVars, fallback)); line != "" {
			appendRaceStatsLine(st, line)
		}
	case event.EventRaceGroupHeader:
		if skipReleaseAnnounce {
			return nil, nil
		}
		appendRaceStatsLine(st, "")
		if line := strings.TrimSpace(p.render("STATS_GROUP_HEADER", vars, "GroupTop")); line != "" {
			appendRaceStatsLine(st, line)
		}
	case event.EventRaceGroup:
		if skipReleaseAnnounce {
			return nil, nil
		}
		perVars := map[string]string{}
		for k, v := range vars {
			perVars[k] = v
		}
		perVars["g_rank"] = vars["g_rank"]
		perVars["g_name"] = vars["g_name"]
		perVars["g_files"] = vars["g_files"]
		perVars["g_mb"] = vars["g_mb"]
		perVars["g_pct"] = vars["g_pct"]
		perVars["g_speed"] = vars["g_speed"]
		fallback := fmt.Sprintf("%s. %s [%sMB/%s Files/%s%%/%s]", perVars["g_rank"], perVars["g_name"], perVars["g_mb"], perVars["g_files"], perVars["g_pct"], perVars["g_speed"])
		if line := strings.TrimSpace(p.render("STATS_GROUP", perVars, fallback)); line != "" {
			appendRaceStatsLine(st, line)
		}
	case event.EventRaceFooter:
		if skipReleaseAnnounce {
			return nil, nil
		}
		if line := p.render("STATS_END", vars, "STATS: -----------====>>>>           END          <<<<====-----------"); strings.TrimSpace(line) != "" {
			appendRaceStatsLine(st, line)
			appendRaceStatsLine(st, "\u00a0")
		}
		if block := flushRaceStats(st); strings.TrimSpace(block) != "" {
			outs = append(outs, plugin.Output{Type: "STATS", Text: block})
		}
	case event.EventNuke:
		nuker := strings.TrimSpace(vars["u_name"])
		if nuker == "" {
			nuker = evt.User
		}
		if multiplier := strings.TrimSpace(vars["multiplier"]); multiplier != "" {
			vars["multiplier_label"] = "x" + multiplier
		}
		outs = append(outs, plugin.Output{Type: "NUKE", Text: p.render("NUKE", vars, fmt.Sprintf("NUKED: [%s] %s", section, rel))})
		if multiplier := strings.TrimSpace(vars["multiplier"]); multiplier != "" && nuker != "" {
			outs = append(outs, plugin.Output{Type: "NUKE", Text: p.render("NUKE_FACTOR", vars, fmt.Sprintf("NUKED: Was nuked factor x%s by %s", multiplier, nuker))})
		}
		if reason := strings.TrimSpace(vars["reason"]); reason != "" {
			outs = append(outs, plugin.Output{Type: "NUKE", Text: p.render("NUKE_REASON", vars, fmt.Sprintf("NUKED: [reason] --> %s", reason))})
		}
		if nukees := strings.TrimSpace(vars["nukees"]); nukees != "" {
			perVars := map[string]string{}
			for k, v := range vars {
				perVars[k] = v
			}
			perVars["nukees_colored"] = colorizeNukees(nukees)
			outs = append(outs, plugin.Output{Type: "NUKE", Text: p.render("NUKE_NUKEES", perVars, fmt.Sprintf("NUKED: [nukees] --> %s", perVars["nukees_colored"]))})
		}
		outs = append(outs, plugin.Output{Type: "NUKE", Text: "\u00a0"})
	case event.EventUnnuke:
		outs = append(outs, plugin.Output{Type: "UNNUKE", Text: p.render("UNNUKE", vars, fmt.Sprintf("UNNUKE: [%s] %s by %s", section, rel, evt.User))})
		if reason := strings.TrimSpace(vars["reason"]); reason != "" {
			outs = append(outs, plugin.Output{Type: "UNNUKE", Text: p.render("UNNUKE_REASON", vars, "UNNUKE: [reason] --> "+reason)})
		}
		outs = append(outs, plugin.Output{Type: "UNNUKE", Text: "\u00a0"})
	case event.EventAutonukeWarn:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			tag := strings.TrimSpace(vars["tag"])
			if tag == "" {
				tag = "AUTONUKE"
			}
			owner := strings.TrimSpace(vars["owner"])
			if owner == "" {
				owner = "-"
			}
			message = fmt.Sprintf("%s: [%s] %s owner=%s warned after %s, nukes after %s",
				tag, section, rel, owner, vars["warn_after"], vars["nuke_after"])
			if detail := strings.TrimSpace(vars["detail"]); detail != "" {
				message += " [" + detail + "]"
			}
		}
		message = humanizeAutonukeMessage(message, vars["tag"], vars["reason"])
		vars["message"] = message
		// Expose the friendly "AUTONUKE INCOMPLETE"-style label so the theme can
		// colorize it (and the section/release) per-part like the NUKE line.
		vars["autonuke_label"] = friendlyAutonukeLabel(vars["tag"], vars["reason"])
		vars["autonuke_reason"] = strings.TrimSpace(strings.TrimPrefix(vars["autonuke_label"], "AUTONUKE"))
		lines := []string{p.render("AUTONUKEWARN", vars, "WARN: "+message)}
		for _, field := range []struct{ key, template string }{
			{"owner", "AUTONUKEWARN_OWNER"},
			{"warn_after", "AUTONUKEWARN_AGE"},
			{"nuke_after", "AUTONUKEWARN_DEADLINE"},
		} {
			if strings.TrimSpace(vars[field.key]) != "" {
				if line := p.render(field.template, vars, ""); strings.TrimSpace(line) != "" {
					lines = append(lines, line)
				}
			}
		}
		outs = append(outs, plugin.Output{Type: "AUTONUKEWARN", Text: strings.Join(lines, "\n") + "\n\u00a0"})
	case event.EventAutonukeDelete:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			message = fmt.Sprintf("deleted old nuked release [%s] %s", section, rel)
			if reason := strings.TrimSpace(vars["reason"]); reason != "" {
				message += " (" + reason + ")"
			}
		}
		vars["message"] = message
		vars["delete_detail"] = vars["reason"]
		if strings.HasPrefix(strings.ToLower(vars["reason"]), "deleted after ") {
			vars["delete_detail"] = "Deleted release after " + vars["reason"][len("deleted after "):]
		}
		line := p.render("AUTONUKEDELETE", vars, "AUTONUKE: "+message)
		if strings.TrimSpace(vars["delete_detail"]) != "" {
			if detail := p.render("AUTONUKEDELETE_DETAIL", vars, ""); strings.TrimSpace(detail) != "" {
				line += "\n" + detail
			}
		}
		outs = append(outs, plugin.Output{Type: "AUTONUKEDELETE", Text: line + "\n\u00a0"})
	case event.EventUserChange:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			actor := strings.TrimSpace(vars["actor"])
			if actor == "" {
				actor = strings.TrimSpace(vars["user"])
			}
			message = fmt.Sprintf("%s %s %s %s", vars["action"], vars["target_type"], vars["target"], vars["field"])
			if oldValue, newValue := strings.TrimSpace(vars["old_value"]), strings.TrimSpace(vars["new_value"]); oldValue != "" && newValue != "" {
				message += fmt.Sprintf(" %s -> %s", oldValue, newValue)
			} else if newValue != "" {
				message += " " + newValue
			}
			if detail := strings.TrimSpace(vars["detail"]); detail != "" {
				message += " (" + detail + ")"
			}
			if actor != "" {
				message += " by " + actor
			}
		}
		vars["message"] = strings.TrimSpace(message)
		outs = append(outs, plugin.Output{Type: "USERCHANGE", Text: p.render("USERCHANGE", vars, "USER: "+vars["message"])})
	case event.EventLoginFail:
		key := loginFailKey(vars)
		if key != "|||" && p.loginFailCooldown > 0 {
			if last, ok := p.lastLoginFail[key]; ok && time.Since(last) < p.loginFailCooldown {
				return nil, nil
			}
			p.lastLoginFail[key] = time.Now()
		}
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			mask := strings.TrimSpace(vars["remote_mask"])
			ip := strings.TrimSpace(vars["remote_ip"])
			source := mask
			if source == "" {
				source = ip
			}
			banHint := ""
			if mask != "" {
				banHint = fmt.Sprintf(" Ban: SITE BAN %s", mask)
			}
			switch strings.TrimSpace(vars["reason"]) {
			case "user_deleted":
				message = fmt.Sprintf("%s could not log in, user deleted.", vars["username"])
			case "account_disabled":
				message = fmt.Sprintf("%s could not log in, account disabled.", vars["username"])
			case "account_banned":
				message = fmt.Sprintf("%s could not log in, account banned.", vars["username"])
			case "bad_password":
				message = fmt.Sprintf("%s could not log in, bad password from %s.%s", vars["username"], source, banHint)
			case "ip_not_allowed":
				message = fmt.Sprintf("%s could not log in, ip %s not allowed (%s).%s", vars["username"], ip, source, banHint)
			case "no_ip_masks":
				message = fmt.Sprintf("%s could not log in, no IP masks configured in userfile.", vars["username"])
			case "ip_restricted":
				message = fmt.Sprintf("%s could not log in, ip %s not in whitelist (%s).%s", vars["username"], ip, source, banHint)
			case "disk_full":
				message = fmt.Sprintf("%s could not log in, disk full%s.", vars["username"], loginStorageDetail(vars))
			case "storage_error":
				message = fmt.Sprintf("%s could not log in, storage write failed%s.", vars["username"], loginStorageDetail(vars))
			case "account_expired":
				message = fmt.Sprintf("%s could not log in, account expired.", vars["username"])
			case "tls_required":
				message = fmt.Sprintf("%s could not log in, TLS required.", vars["username"])
			case "plugin_rejected":
				message = fmt.Sprintf("%s could not log in, denied by plugin from %s.%s", vars["username"], source, banHint)
			case "max_logins_reached":
				message = fmt.Sprintf("%s could not log in, login limit reached.", vars["username"])
			case "group_simult_reached":
				message = fmt.Sprintf("%s could not log in, group login limit reached.", vars["username"])
			default:
				message = fmt.Sprintf("denied unknown connection from %s at ip %s.%s", source, ip, banHint)
			}
		}
		vars["message"] = message
		outs = append(outs, plugin.Output{Type: "LOGIN", Text: p.render("LOGINFAIL", vars, "LOGiN: "+message)})
	case event.EventSelfIP:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			switch strings.ToUpper(strings.TrimSpace(vars["action"])) {
			case "ADD":
				message = fmt.Sprintf("%s added IP(s): %s.", vars["username"], vars["new_ip"])
			case "DEL":
				message = fmt.Sprintf("%s removed IP(s): %s.", vars["username"], vars["old_ip"])
			case "CHG":
				message = fmt.Sprintf("%s changed IP: %s -> %s.", vars["username"], vars["old_ip"], vars["new_ip"])
			default:
				message = fmt.Sprintf("%s updated IP settings.", vars["username"])
			}
		}
		vars["message"] = message
		outs = append(outs, plugin.Output{Type: "SELFIP", Text: p.render("SELFIPLOG", vars, "IPLOG: "+message)})
	case event.EventSlaveAuthFail:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			remote := strings.TrimSpace(vars["remote_addr"])
			if remote == "" {
				remote = strings.TrimSpace(vars["remote_ip"])
			}
			reason := strings.TrimSpace(vars["reason"])
			strikes := strings.TrimSpace(vars["strikes"])
			limit := strings.TrimSpace(vars["limit"])
			switch strings.ToLower(strings.TrimSpace(vars["action"])) {
			case "deny":
				message = fmt.Sprintf("denied slave-port connection from %s - %s", remote, reason)
			case "ban":
				until := strings.TrimSpace(vars["banned_until"])
				message = fmt.Sprintf("slave port banned %s after %s/%s failed handshakes - %s", remote, strikes, limit, reason)
				if until != "" && until != "0001-01-01T00:00:00Z" {
					message += " (until " + until + ")"
				}
			case "blocked":
				message = fmt.Sprintf("blocked banned slave-port source %s", remote)
			default:
				message = fmt.Sprintf("slave auth failed from %s (%s/%s) - %s", remote, strikes, limit, reason)
			}
		}
		vars["message"] = message
		outs = append(outs, plugin.Output{Type: "SLAVEAUTH", Text: p.render("SLAVEAUTHFAIL", vars, "SLAVESEC: "+message)})
	case event.EventSlowUploadWarn:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			message = fmt.Sprintf("%s/%s is uploading %s at %sKB/s in %s, verifying for %ss before kick.",
				vars["username"], vars["group"], vars["filename"], vars["speed_kbps"], vars["path"], vars["verify_seconds"])
		}
		vars["message"] = message
		outs = p.appendTargeted(outs, "SLOWUPLOADWARN", p.render("SLOWUPLOADWARN", vars, "SLOWUP: "+message), p.slowUploadWarnChans)
	case event.EventSlowUploadKick:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			target := strings.TrimSpace(vars["relname"])
			if target == "" {
				target = strings.TrimSpace(vars["path"])
			}
			message = fmt.Sprintf("%s/%s slowup kick: %s @ %sKB/s (< %sKB/s) in %s.",
				vars["username"], vars["group"], vars["filename"], vars["speed_kbps"], vars["min_speed_kbps"], target)
			if secs := strings.TrimSpace(vars["tempban_seconds"]); secs != "" && secs != "0" {
				message += fmt.Sprintf(" Tempban %ss.", secs)
			}
		}
		vars["message"] = message
		outs = p.appendTargeted(outs, "SLOWUPLOADKICK", p.render("SLOWUPLOADKICK", vars, "SLOWUP: "+message), p.slowUploadKickChans)
	case event.EventSlowDownloadWarn:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			message = fmt.Sprintf("%s/%s is downloading %s at %sKB/s from %s, verifying for %ss before kick.",
				vars["username"], vars["group"], vars["filename"], vars["speed_kbps"], vars["path"], vars["verify_seconds"])
		}
		vars["message"] = message
		outs = p.appendTargeted(outs, "SLOWDOWNLOADWARN", p.render("SLOWDOWNLOADWARN", vars, "SLOWDN: "+message), p.slowDnWarnChans)
	case event.EventSlowDownloadKick:
		message := strings.TrimSpace(vars["message"])
		if message == "" {
			target := strings.TrimSpace(vars["relname"])
			if target == "" {
				target = strings.TrimSpace(vars["path"])
			}
			message = fmt.Sprintf("%s/%s slowdn kick: %s @ %sKB/s (< %sKB/s) from %s.",
				vars["username"], vars["group"], vars["filename"], vars["speed_kbps"], vars["min_speed_kbps"], target)
			if secs := strings.TrimSpace(vars["tempban_seconds"]); secs != "" && secs != "0" {
				message += fmt.Sprintf(" Tempban %ss.", secs)
			}
		}
		vars["message"] = message
		outs = p.appendTargeted(outs, "SLOWDOWNLOADKICK", p.render("SLOWDOWNLOADKICK", vars, "SLOWDN: "+message), p.slowDnKickChans)
	case event.EventPre:
		group := vars["group"]
		if group == "" {
			group = evt.Group
		}
		fallback := fmt.Sprintf("PRE: [%s] %s by %s - %s/%sF%s", section, rel, group, vars["t_mbytes"], vars["t_files"], vars["pre_suffix"])
		outs = append(outs, plugin.Output{Type: "PRE", Text: p.render("PRE", vars, fallback)})
	case event.EventPreAudioInfo:
		meta := []string{}
		if head := strings.TrimSpace(vars["pre_audio_head"]); head != "" {
			meta = append(meta, head)
		}
		if value := strings.TrimSpace(vars["genre"]); value != "" && !strings.EqualFold(value, "N/A") {
			meta = append(meta, value)
		}
		if value := strings.TrimSpace(vars["year"]); value != "" && !strings.EqualFold(value, "N/A") {
			meta = append(meta, value)
		}
		if value := strings.TrimSpace(vars["bitrate"]); value != "" && !strings.EqualFold(value, "N/A") {
			meta = append(meta, value)
		}
		suffix := ""
		if len(meta) > 0 {
			suffix = " :: " + strings.Join(meta, " :: ")
		}
		fallback := fmt.Sprintf("PRE: [%s] %s%s", section, rel, suffix)
		outs = append(outs, plugin.Output{Type: "PRE", Text: p.render("PREAUDIOINFO", vars, fallback)})
	case event.EventPreMovieInfo:
		title := strings.TrimSpace(vars["title"])
		year := strings.TrimSpace(vars["year"])
		genre := strings.TrimSpace(vars["genre"])
		rating := strings.TrimSpace(vars["rating"])
		head := rel
		if title != "" {
			head = title
			if year != "" && !strings.EqualFold(year, "N/A") {
				head = fmt.Sprintf("%s (%s)", title, year)
			}
		}
		parts := []string{head}
		if genre != "" && !strings.EqualFold(genre, "N/A") {
			parts = append(parts, genre)
		}
		if rating != "" && !strings.EqualFold(rating, "N/A") {
			parts = append(parts, rating)
		}
		fallback := fmt.Sprintf("PRE: [%s] %s :: %s", section, rel, strings.Join(parts, " :: "))
		outs = append(outs, plugin.Output{Type: "PRE", Text: p.render("PREMOVIEINFO", vars, fallback)})
	case event.EventPreTVInfo:
		parts := []string{}
		if episode := strings.TrimSpace(vars["episode"]); episode != "" && !strings.EqualFold(episode, "N/A") {
			parts = append(parts, episode)
		}
		if genre := strings.TrimSpace(vars["genre"]); genre != "" && !strings.EqualFold(genre, "N/A") {
			parts = append(parts, genre)
		}
		if tvType := strings.TrimSpace(vars["type"]); tvType != "" && !strings.EqualFold(tvType, "N/A") {
			parts = append(parts, tvType)
		}
		if network := strings.TrimSpace(vars["network"]); network != "" && !strings.EqualFold(network, "N/A") {
			parts = append(parts, network)
		}
		if language := strings.TrimSpace(vars["language"]); language != "" && !strings.EqualFold(language, "N/A") {
			parts = append(parts, language)
		}
		fallback := fmt.Sprintf("PRE: [%s] %s", section, rel)
		if len(parts) > 0 {
			fallback += " :: " + strings.Join(parts, " :: ")
		}
		outs = append(outs, plugin.Output{Type: "PRE", Text: p.render("PRETVINFO", vars, fallback)})
	case event.EventPreBW:
		fallback := fmt.Sprintf("PREBW: [%s] %s :: %s%s @ %s%s :: Highest %s%s",
			section, rel,
			vars["traffic_val"], vars["traffic_unit"],
			vars["avg_val"], vars["avg_unit"],
			vars["peak_val"], vars["peak_unit"])
		outs = append(outs, plugin.Output{Type: "PREBW", Text: p.render("PREBW", vars, fallback)})
	case event.EventPreBWInterval:
		fallback := fmt.Sprintf("PREBW: [%s] %s :: %s%s@%ss :: %s%s@%ss :: %s%s@%ss :: %s%s@%ss :: %s%s@%ss :: Highest %s%s",
			section, rel,
			vars["b1"], vars["u1"], vars["t1"],
			vars["b2"], vars["u2"], vars["t2"],
			vars["b3"], vars["u3"], vars["t3"],
			vars["b4"], vars["u4"], vars["t4"],
			vars["b5"], vars["u5"], vars["t5"],
			vars["peak_val"], vars["peak_unit"])
		outs = append(outs, plugin.Output{Type: "PREBW", Text: p.render("PREBWINTERVAL", vars, fallback)})
	case event.EventPreBWUser:
		fallback := fmt.Sprintf("PREBW: [%s] %s :: %s%s/%sF @ %s%s :: Highest %s%s",
			section, vars["user"],
			vars["size_val"], vars["size_unit"], vars["cnt_files"],
			vars["avg_val_user"], vars["avg_unit_user"],
			vars["peak_val_user"], vars["peak_unit_user"])
		outs = append(outs, plugin.Output{Type: "PREBW", Text: p.render("PREBWUSER", vars, fallback)})
	case event.EventNewPreTime:
		if p.shouldInlinePretime() {
			p.emitInlinePretime(evt, section, rel, vars)
			return nil, nil
		}
		if shouldSuppressLatePretime(st) || p.isReleaseCompleted(section, rel, evt.Path) {
			return nil, nil
		}
		fallback := fmt.Sprintf("PRETiME: [%s] %s :: OK :: released %s ago", section, rel, vars["preage"])
		outs = append(outs, plugin.Output{Type: "NEWPRETIME", Text: p.render("NEWPRETIME", vars, fallback)})
	case event.EventOldPreTime:
		if p.shouldInlinePretime() {
			p.emitInlinePretime(evt, section, rel, vars)
			return nil, nil
		}
		if shouldSuppressLatePretime(st) || p.isReleaseCompleted(section, rel, evt.Path) {
			return nil, nil
		}
		fallback := fmt.Sprintf("PRETiME: [%s] %s :: BAD :: released %s ago", section, rel, vars["preage"])
		outs = append(outs, plugin.Output{Type: "OLDPRETIME", Text: p.render("OLDPRETIME", vars, fallback)})
	}
	return outs, nil
}

func formatAudioInfoSummary(vars map[string]string) string {
	parts := []string{}
	if genre := strings.TrimSpace(vars["genre"]); genre != "" {
		parts = append(parts, "Get ready for some "+genre)
	} else {
		parts = append(parts, "Get ready for some audio")
	}
	if year := strings.TrimSpace(vars["year"]); year != "" {
		parts = append(parts, "from "+year)
	}
	if sampleRate := strings.TrimSpace(vars["sample_rate"]); sampleRate != "" {
		parts = append(parts, "at "+sampleRate+"Hz")
	}
	audioTail := []string{}
	if channels := strings.TrimSpace(vars["channels"]); channels != "" {
		audioTail = append(audioTail, channels)
	}
	if bitrate := strings.TrimSpace(vars["bitrate"]); bitrate != "" {
		audioTail = append(audioTail, bitrate)
	}
	if mode := strings.TrimSpace(vars["bitrate_mode"]); mode != "" {
		audioTail = append(audioTail, "("+mode+")")
	}
	if len(audioTail) > 0 {
		parts = append(parts, "in "+strings.Join(audioTail, " "))
	}
	return strings.Join(parts, " ")
}

func formatSampleVideoLabel(vars map[string]string) string {
	codec := strings.TrimSpace(vars["video_format"])
	width := strings.TrimSpace(vars["width"])
	height := strings.TrimSpace(vars["height"])
	switch {
	case codec != "" && width != "" && height != "":
		return codec + " " + width + "x" + height
	case codec != "":
		return codec
	case width != "" && height != "":
		return width + "x" + height
	default:
		return "Unknown"
	}
}

func formatSampleAudioLabel(vars map[string]string) string {
	codec := strings.TrimSpace(vars["audio_format"])
	channels := strings.TrimSpace(vars["channels"])
	switch {
	case codec != "" && channels != "":
		return codec + " " + channels
	case codec != "":
		return codec
	case channels != "":
		return channels
	default:
		return "None"
	}
}

func formatSampleSubtitleLabel(vars map[string]string) string {
	if subs := strings.TrimSpace(vars["subtitle_format"]); subs != "" {
		return subs
	}
	return "None"
}

func formatSampleDurationLabel(vars map[string]string) string {
	if duration := strings.TrimSpace(vars["duration"]); duration != "" {
		return duration
	}
	return "Unknown"
}

func isReleaseDir(eventPath, section string) bool {
	clean := path.Clean(eventPath)
	parent := path.Dir(clean)
	sectionName := strings.Trim(section, "/")
	if strings.EqualFold(path.Base(parent), sectionName) {
		return true
	}
	if strings.EqualFold(sectionName, "REQUESTS") && isRequestWrapperName(path.Base(parent)) && strings.EqualFold(path.Base(path.Dir(parent)), "REQUESTS") {
		return true
	}

	datedParent := path.Base(parent)
	if !isDateDir(datedParent) {
		return false
	}
	return strings.EqualFold(path.Base(path.Dir(parent)), sectionName)
}

func isRequestRaceUploadPath(eventPath, section string) bool {
	if !strings.EqualFold(strings.Trim(section, "/"), "REQUESTS") {
		return false
	}
	clean := strings.Trim(path.Clean("/"+strings.TrimSpace(eventPath)), "/")
	if clean == "" {
		return false
	}
	parts := strings.Split(clean, "/")
	return len(parts) >= 3 && strings.EqualFold(parts[0], "REQUESTS") && isRequestWrapperName(parts[1])
}

func isDirectRequestWrapperPath(dirPath string) bool {
	clean := strings.Trim(path.Clean("/"+strings.TrimSpace(dirPath)), "/")
	if clean == "" {
		return false
	}
	parts := strings.Split(clean, "/")
	return len(parts) == 2 && strings.EqualFold(parts[0], "REQUESTS") && isRequestWrapperName(parts[1])
}

func isRequestWrapperName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return strings.HasPrefix(upper, "REQ-") || strings.HasPrefix(upper, "FILLED-")
}

func isSectionRootMetadataEvent(evt *event.Event, section string) bool {
	if evt == nil {
		return false
	}
	clean := strings.Trim(path.Clean("/"+strings.TrimSpace(evt.Path)), "/")
	if clean == "" {
		return false
	}
	parts := strings.Split(clean, "/")
	section = strings.Trim(section, "/")
	if len(parts) == 1 {
		return strings.EqualFold(parts[0], section)
	}
	if len(parts) == 2 {
		switch strings.ToUpper(parts[0]) {
		case "FOREIGN", "PRE", "ARCHIVE":
			return strings.EqualFold(parts[1], section)
		}
	}
	return false
}

func stripRequestWrapperPrefix(name string) string {
	trimmed := strings.TrimSpace(name)
	upper := strings.ToUpper(trimmed)
	for _, prefix := range []string{"FILLED-", "REQ-"} {
		if strings.HasPrefix(upper, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return trimmed
}

func isDateDir(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) == 4 {
		for _, r := range name {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$|^\d{8}$`).MatchString(name)
}
