package slowkick

import (
	"testing"
	"time"

	"weaveftpd/internal/plugin"
)

func TestSlaveGraceUsesFirstDataByte(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		start    time.Time
		wantKick bool
	}{
		{"no_first_byte", time.Time{}, false},
		{"first_byte_100ms_ago", now.Add(-100 * time.Millisecond), false},
		{"slow_after_grace", now.Add(-3 * time.Second), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kicked := false
			h := New()
			h.monitorUploads = true
			h.minUsersOnline = 0
			h.minUploadSpeedBytes = 3000 * 1024
			h.uploadGrace = 2 * time.Second
			h.tempbanAfterKick = false
			h.svc = &plugin.Services{
				ListActiveSessions: func() []plugin.ActiveSession {
					return []plugin.ActiveSession{{ID: 1, User: "tester", LoggedIn: true,
						TransferDirection: "upload", TransferPath: "/TV/release/file.r00",
						TransferStartedAt: now.Add(-3 * time.Second), TransferSlaveName: "LOCAL", TransferSlaveIdx: 42}}
				},
				GetLiveTransferStats: func() []plugin.LiveTransferStat {
					return []plugin.LiveTransferStat{{SlaveName: "LOCAL", TransferIndex: 42,
						Path: "/TV/release/file.r00", StartedAt: tc.start}}
				},
				DisconnectSession: func(uint64) bool { kicked = true; return true },
			}
			h.checkActiveTransfers(now)
			if kicked != tc.wantKick {
				t.Fatalf("kicked=%v, want %v", kicked, tc.wantKick)
			}
		})
	}
}
