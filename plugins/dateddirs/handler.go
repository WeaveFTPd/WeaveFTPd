package dateddirs

import (
	"fmt"
	"log"
	"path"
	"strings"
	"sync"
	"time"

	"weaveftpd/internal/plugin"
	"weaveftpd/internal/timeutil"
	"weaveftpd/internal/user"
)

type Handler struct {
	svc                  *plugin.Services
	sections             []string
	format               string
	todaySymlink         bool
	symlinkPrefix        string
	readOnlyAfterMinutes int
	debug                bool

	mu        sync.Mutex
	lastDay   string
	stopCh    chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
}

func New() *Handler {
	return &Handler{
		stopCh: make(chan struct{}),
	}
}

func (h *Handler) Name() string { return "dateddirs" }

func (h *Handler) Init(svc *plugin.Services, cfg map[string]interface{}) error {
	h.svc = svc
	h.sections = stringSliceConfig(cfg, "sections")
	h.format = normalizeFormat(stringConfig(cfg, "format", "MMDD"))
	h.todaySymlink = boolConfig(cfg, "today_symlink", true)
	h.symlinkPrefix = stringConfig(cfg, "symlink_prefix", "!Today_")
	h.readOnlyAfterMinutes = intConfig(cfg, "readonly_after_minutes", 60)
	h.debug = boolConfig(cfg, "debug", svc != nil && svc.Debug)
	if h.readOnlyAfterMinutes < 0 {
		h.readOnlyAfterMinutes = 60
	}
	h.startOnce.Do(func() { go h.loop() })
	if h.debug {
		log.Printf("[DATEDDIRS] initialized sections=%v", h.sections)
	}
	return nil
}

func (h *Handler) OnEvent(evt *plugin.Event) error { return nil }

// Normal uploads arrive here after VFS link resolution. Fail closed if a
// configured dated alias was not resolved, rather than creating it on disk.
func (h *Handler) validateResolvedLink(target string) error {
	if !h.todaySymlink {
		return nil
	}
	first := strings.Split(strings.TrimPrefix(path.Clean("/"+target), "/"), "/")[0]
	for _, section := range h.sections {
		section = strings.Trim(strings.TrimSpace(section), "/")
		if section != "" && strings.EqualFold(first, h.symlinkPrefix+section) {
			return fmt.Errorf("virtual dated link is not resolved: use /%s or retry after link initialization", section)
		}
	}
	return nil
}

func (h *Handler) ValidateMKDir(_ *user.User, target string) error {
	return h.validateResolvedLink(target)
}
func (h *Handler) ValidateUpload(_ *user.User, target string) error {
	return h.validateResolvedLink(target)
}

func (h *Handler) Stop() error {
	h.stopOnce.Do(func() { close(h.stopCh) })
	return nil
}

func (h *Handler) loop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	h.apply(timeutil.Now())
	for {
		select {
		case <-h.stopCh:
			return
		case now := <-ticker.C:
			h.apply(timeutil.In(now))
		}
	}
}

func (h *Handler) apply(now time.Time) {
	if h.svc == nil || h.svc.Bridge == nil {
		return
	}
	today := formatDateDir(now, h.format)
	yesterday := formatDateDir(now.AddDate(0, 0, -1), h.format)

	h.mu.Lock()
	lastDay := h.lastDay
	announce := lastDay != "" && lastDay != today
	h.mu.Unlock()

	for _, section := range h.sections {
		section = strings.Trim(strings.TrimSpace(section), "/")
		if section == "" {
			continue
		}

		todayPath := "/" + section + "/" + today
		if !h.pathExists(todayPath) {
			h.svc.Bridge.MakeDir(todayPath, "WeaveFTPd", "WeaveFTPd")
		}

		linkPath := ""
		if h.todaySymlink {
			linkPath = "/" + h.symlinkPrefix + section
			current := h.symlinkCurrent(linkPath, todayPath)
			// Register ownership even when a restored snapshot already has the link.
			if err := h.svc.Bridge.VFSSymlink(linkPath, todayPath); err != nil {
				if h.debug {
					log.Printf("[DATEDDIRS] symlink %s -> %s failed: %v", linkPath, todayPath, err)
				}
			} else if current {
				if h.debug {
					log.Printf("[DATEDDIRS] symlink %s already points to %s", linkPath, todayPath)
				}
			}
		}

		if announce && h.svc.EmitEvent != nil {
			h.svc.EmitEvent("NEWDAY", todayPath, today, section, 0, 0, map[string]string{
				"date":     today,
				"dirpath":  todayPath,
				"linkpath": linkPath,
				"symlink":  boolString(h.todaySymlink),
			})
		}

		if h.readOnlyAfterMinutes > 0 && minutesSinceMidnight(now) >= h.readOnlyAfterMinutes {
			yesterdayPath := "/" + section + "/" + yesterday
			if h.pathExists(yesterdayPath) && !h.pathMode(yesterdayPath, 0555) {
				_ = h.svc.Bridge.Chmod(yesterdayPath, 0555)
			}
		}
	}

	h.mu.Lock()
	h.lastDay = today
	h.mu.Unlock()
}

func (h *Handler) symlinkCurrent(linkPath, targetPath string) bool {
	if h.svc == nil || h.svc.Bridge == nil {
		return false
	}
	linkPath = path.Clean(linkPath)
	parent := path.Dir(linkPath)
	name := path.Base(linkPath)
	targetPath = path.Clean(targetPath)
	for _, entry := range h.svc.Bridge.PluginListDir(parent) {
		if entry.Name == name && entry.IsSymlink && path.Clean(entry.LinkTarget) == targetPath {
			return true
		}
	}
	return false
}

func (h *Handler) pathExists(targetPath string) bool {
	if h.svc == nil || h.svc.Bridge == nil {
		return false
	}
	return h.svc.Bridge.FileExists(path.Clean(targetPath))
}

func (h *Handler) pathMode(targetPath string, mode uint32) bool {
	if h.svc == nil || h.svc.Bridge == nil {
		return false
	}
	targetPath = path.Clean(targetPath)
	parent := path.Dir(targetPath)
	name := path.Base(targetPath)
	for _, entry := range h.svc.Bridge.PluginListDir(parent) {
		if entry.Name == name {
			return entry.Mode == mode
		}
	}
	return false
}

func normalizeFormat(format string) string {
	if strings.TrimSpace(format) == "" {
		return "MMDD"
	}
	return strings.TrimSpace(format)
}

func formatDateDir(t time.Time, format string) string {
	format = strings.TrimSpace(format)
	if format == "" {
		format = "MMDD"
	}

	replacer := strings.NewReplacer(
		"WW-YYYY", "{WEEK2}-{ISOYEAR4}",
		"YYYY-WW", "{ISOYEAR4}-{WEEK2}",
		"YYYY", "{YEAR4}",
		"YY", "{YEAR2}",
		"MM", "{MONTH2}",
		"DD", "{DAY2}",
		"WW", "{WEEK2}",
	)
	tokenized := replacer.Replace(format)
	if tokenized == format {
		tokenized = "{MONTH2}{DAY2}"
	}
	isoYear, isoWeek := t.ISOWeek()
	return strings.NewReplacer(
		"{YEAR4}", t.Format("2006"),
		"{YEAR2}", t.Format("06"),
		"{MONTH2}", t.Format("01"),
		"{DAY2}", t.Format("02"),
		"{WEEK2}", fmt.Sprintf("%02d", isoWeek),
		"{ISOYEAR4}", fmt.Sprintf("%04d", isoYear),
	).Replace(tokenized)
}

func minutesSinceMidnight(t time.Time) int {
	return t.Hour()*60 + t.Minute()
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func stringConfig(cfg map[string]interface{}, key, fallback string) string {
	if raw, ok := cfg[key].(string); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	return fallback
}

func boolConfig(cfg map[string]interface{}, key string, fallback bool) bool {
	if raw, ok := cfg[key].(bool); ok {
		return raw
	}
	return fallback
}

func intConfig(cfg map[string]interface{}, key string, fallback int) int {
	switch v := cfg[key].(type) {
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

func stringSliceConfig(cfg map[string]interface{}, key string) []string {
	raw, ok := cfg[key]
	if !ok {
		return nil
	}
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
	case string:
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return nil
	}
}
