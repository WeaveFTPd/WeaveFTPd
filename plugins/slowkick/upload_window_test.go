package slowkick

import (
	"path"
	"strings"
	"testing"
	"time"

	"weaveftpd/internal/plugin"
	"weaveftpd/internal/user"
)

func TestUploadWindowRequiresTenSecondsAndUsesByteDeltas(t *testing.T) {
	h := New()
	start := time.Now()
	for sec := 0; sec <= 10; sec++ {
		speed, ready := h.windowSpeed("x", start, start.Add(time.Duration(sec)*time.Second), int64(sec)*1024, 10*time.Second)
		if ready != (sec == 10) || (ready && speed != 1024) {
			t.Fatalf("second %d: speed=%v ready=%v", sec, speed, ready)
		}
	}
	// A fast recent window must not inherit the initial slow average.
	for sec := 11; sec <= 20; sec++ {
		speed, ready := h.windowSpeed("x", start, start.Add(time.Duration(sec)*time.Second), 10*1024+int64(sec-10)*100*1024, 10*time.Second)
		if sec == 20 && (!ready || speed != 100*1024) {
			t.Fatalf("not a rolling window: %v %v", speed, ready)
		}
	}
}

func TestUploadWindowIgnoresShortDipAndResetsMissingTelemetry(t *testing.T) {
	h := New()
	start := time.Now()
	var bytes int64
	for sec := 0; sec <= 10; sec++ {
		if sec > 0 && sec != 8 {
			bytes += 10 * 1024 * 1024
		}
		speed, ready := h.windowSpeed("x", start, start.Add(time.Duration(sec)*time.Second), bytes, 10*time.Second)
		if sec == 10 && (!ready || speed < 3000*1024) {
			t.Fatalf("short dip incorrectly slow: %v %v", speed, ready)
		}
	}
	if _, ready := h.windowSpeed("x", start, start.Add(15*time.Second), bytes, 10*time.Second); ready {
		t.Fatal("telemetry gap must restart window")
	}
	if _, ready := h.windowSpeed("x", start, start.Add(16*time.Second), 0, 10*time.Second); ready {
		t.Fatal("counter reset must restart window")
	}
	h.pruneKickedTransfers(nil)
	if len(h.samples) != 0 {
		t.Fatal("finished transfers retain samples")
	}
}

func releaseTestHandler(t *testing.T) (*Handler, *plugin.ActiveSession, *plugin.LiveTransferStat, *int) {
	t.Helper()
	h := New()
	start := time.Now()
	snap := &plugin.ActiveSession{ID: 1, User: "tester", LoggedIn: true, TransferDirection: "upload", TransferPath: "/TV/Release/CD1/file.rar", TransferStartedAt: start, TransferSlaveName: "LOCAL", TransferSlaveIdx: 12}
	stat := &plugin.LiveTransferStat{SlaveName: "LOCAL", TransferIndex: 12, Path: snap.TransferPath, StartedAt: start, SpeedBytes: 999999999}
	aborts := new(int)
	h.svc = &plugin.Services{
		ListActiveSessions:   func() []plugin.ActiveSession { return []plugin.ActiveSession{*snap} },
		GetLiveTransferStats: func() []plugin.LiveTransferStat { return []plugin.LiveTransferStat{*stat} },
		ReleaseRoot: func(p string) string {
			parts := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
			if len(parts) < 3 {
				return ""
			}
			return "/" + strings.Join(parts[:2], "/")
		},
		AbortSessionTransfer: func(s plugin.ActiveSession, reason string) bool { *aborts++; return true },
		DisconnectSession:    func(uint64) bool { t.Fatal("release mode disconnected FTP session"); return false },
	}
	if err := h.applyConfig(map[string]interface{}{
		"enabled": true, "ban_scope": "release", "upload_window_seconds": 10,
		"verify_upload_seconds": 2, "min_upload_speed_kbps": 3000,
		"min_users_online": 0, "tempban_seconds": 30,
	}, true); err != nil {
		t.Fatal(err)
	}
	return h, snap, stat, aborts
}

func TestReleaseBanAbortsAfterWindowAndIsScoped(t *testing.T) {
	h, snap, stat, aborts := releaseTestHandler(t)
	start := stat.StartedAt
	for sec := 0; sec <= 10; sec++ {
		stat.Transferred = int64(sec) * 1024
		h.checkActiveTransfers(start.Add(time.Duration(sec) * time.Second))
		if sec < 10 && *aborts != 0 {
			t.Fatal("premature abort")
		}
	}
	if *aborts != 1 {
		t.Fatalf("aborts=%d", *aborts)
	}
	u := &user.User{Name: "TESTER"}
	if err := h.ValidateLogin(u, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/TV/Release/other.rar", "/TV/Release/Subs/sub.rar"} {
		if err := h.ValidateUpload(u, p); err == nil {
			t.Fatalf("ban bypass: %s", p)
		}
	}
	if err := h.ValidateUpload(u, "/TV/Release2/file.rar"); err != nil {
		t.Fatal(err)
	}
	if err := h.ValidateUpload(&user.User{Name: "other"}, snap.TransferPath); err != nil {
		t.Fatal(err)
	}
	h.checkActiveTransfers(start.Add(11 * time.Second))
	if *aborts != 1 {
		t.Fatal("duplicate abort")
	}
	h.pruneExpiredTempBans(time.Now().Add(time.Minute))
	if err := h.ValidateUpload(u, snap.TransferPath); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseBanIsPresentDuringAbortAndRolledBackOnFailure(t *testing.T) {
	h, snap, _, _ := releaseTestHandler(t)
	h.svc.AbortSessionTransfer = func(s plugin.ActiveSession, reason string) bool {
		if err := h.ValidateUpload(&user.User{Name: s.User}, s.TransferPath); err == nil {
			t.Fatal("retry gap during abort")
		}
		return false
	}
	h.kickSlowTransfer(h.snapshotConfig(), *snap, 100, transferPolicy{direction: "upload", minSpeedBytes: 3000 * 1024})
	if len(h.releaseBans) != 0 || len(h.kickedTransfers) != 0 {
		t.Fatal("failed abort retained ban")
	}
}

func TestReleaseModeUnknownRootDoesNotKick(t *testing.T) {
	h, snap, _, aborts := releaseTestHandler(t)
	h.svc.ReleaseRoot = func(string) string { return "" }
	h.kickSlowTransfer(h.snapshotConfig(), *snap, 1, transferPolicy{direction: "upload"})
	if *aborts != 0 || len(h.releaseBans) != 0 {
		t.Fatal("unknown release must not be banned")
	}
}

func TestUploadWindowRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []map[string]interface{}{{"ban_scope": "typo"}, {"upload_window_seconds": -1}, {"upload_window_seconds": 301}} {
		if err := New().applyConfig(cfg, true); err == nil {
			t.Fatalf("accepted %v", cfg)
		}
	}
}

func TestReleaseBanFailedAbortPreservesExistingBan(t *testing.T) {
	h, snap, _, _ := releaseTestHandler(t)
	key := releaseBanKey{"tester", "/TV/Release"}
	previous := time.Now().Add(time.Minute)
	h.releaseBans = map[releaseBanKey]time.Time{key: previous}
	h.svc.AbortSessionTransfer = func(plugin.ActiveSession, string) bool { return false }
	h.kickSlowTransfer(h.snapshotConfig(), *snap, 100, transferPolicy{direction: "upload"})
	if h.releaseBans[key] != previous {
		t.Fatal("existing ban lost on failed abort")
	}
	h.enabled = false
	if err := h.ValidateUpload(&user.User{Name: "tester"}, snap.TransferPath); err != nil {
		t.Fatal("disabled plugin enforced ban:", err)
	}
}

func TestLocalUploadWindowStartsAtObservedProgress(t *testing.T) {
	h := New()
	start := time.Now()
	for sec := 0; sec <= 10; sec++ {
		speed, ready := h.windowSpeed("local", time.Time{}, start.Add(time.Duration(sec)*time.Second), 1000000+int64(sec)*1024, 10*time.Second)
		if ready != (sec == 10) || (ready && speed != 1024) {
			t.Fatalf("local window: %d %v %v", sec, speed, ready)
		}
	}
}
