package slowkick

import (
	"fmt"
	"math"
	"path"
	"strings"
	"time"

	"weaveftpd/internal/user"
)

type speedSample struct {
	at    time.Time
	bytes int64
}

type releaseBanKey struct {
	user string
	root string
}

func (h *Handler) clearSamples(key string) {
	h.mu.Lock()
	delete(h.samples, key)
	h.mu.Unlock()
}

func (h *Handler) windowSpeed(key string, started, now time.Time, bytes int64, window time.Duration) (float64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if key == "" || bytes < 0 || now.Before(started) {
		delete(h.samples, key)
		return 0, false
	}
	if h.samples == nil {
		h.samples = make(map[string][]speedSample)
	}
	samples := h.samples[key]
	if len(samples) > 0 {
		last := samples[len(samples)-1]
		if !now.After(last.at) || bytes < last.bytes || now.Sub(last.at) > 3*slowkickMonitorInterval {
			// Missing telemetry is not evidence of a slow sender.
			h.samples[key] = []speedSample{{now, bytes}}
			return 0, false
		}
	} else if !started.IsZero() && now.Sub(started) <= window {
		samples = append(samples, speedSample{started, 0})
	}
	if len(samples) == 0 || now.After(samples[len(samples)-1].at) {
		samples = append(samples, speedSample{now, bytes})
	}
	cutoff := now.Add(-window)
	for len(samples) > 1 && !samples[1].at.After(cutoff) {
		samples = samples[1:]
	}
	h.samples[key] = samples
	first := samples[0]
	if now.Sub(first.at) < window {
		return 0, false
	}
	return float64(bytes-first.bytes) / now.Sub(first.at).Seconds(), true
}

func (h *Handler) releaseRoot(filePath string) string {
	if h.svc == nil || h.svc.ReleaseRoot == nil {
		return ""
	}
	root := h.svc.ReleaseRoot(filePath)
	if root == "" || root == "/" || root == "." {
		return ""
	}
	return path.Clean(root)
}

func (h *Handler) ValidateUpload(u *user.User, targetPath string) error {
	cfg := h.snapshotConfig()
	if u == nil || !cfg.enabled || cfg.banScope != "release" || !cfg.monitorUploads || !cfg.tempbanAfterKick || cfg.tempbanDuration <= 0 {
		return nil
	}
	if _, excluded := cfg.excludeUsers[strings.ToLower(strings.TrimSpace(u.Name))]; excluded {
		return nil
	}
	if _, excluded := cfg.excludeGroups[strings.ToLower(strings.TrimSpace(u.PrimaryGroup))]; excluded {
		return nil
	}
	key := releaseBanKey{strings.ToLower(strings.TrimSpace(u.Name)), h.releaseRoot(targetPath)}
	if key.root == "" {
		return nil
	}
	h.mu.Lock()
	until, banned := h.releaseBans[key]
	if banned && !until.After(time.Now()) {
		delete(h.releaseBans, key)
		banned = false
	}
	h.mu.Unlock()
	if !banned {
		return nil
	}
	seconds := int(math.Ceil(time.Until(until).Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Errorf("uploads to this release temporarily blocked after slow upload, retry in %ds", seconds)
}
