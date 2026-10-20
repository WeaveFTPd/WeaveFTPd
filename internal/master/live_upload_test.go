package master

import (
	"testing"
	"time"
)

func TestPendingPayloadUploadIsRoutableWithoutCompletingRelease(t *testing.T) {
	sm := NewSlaveManager("127.0.0.1", 1099, false, "", "", 60)
	rs := &RemoteSlave{name: "LIVE"}
	rs.online.Store(true)
	rs.available.Store(true)
	sm.slaves["LIVE"] = rs
	b := &Bridge{sm: sm}
	p := "/RACE/Release/file.r00"
	b.notePendingUpload(p, "LIVE", "racer", "Test", 0)
	if got := sm.GetVFS().GetFile(p); got != nil {
		t.Fatalf("upload prematurely entered completed VFS: %+v", got)
	}
	if b.GetFileSize(p) < 0 || !b.FileExists(p) {
		t.Fatal("PRET/RETR cannot see live payload")
	}
	if got := b.selectSlaveForDownloadIncludingPending(p); got != rs {
		t.Fatal("download not routed to uploading slave")
	}
	entries := b.ListDir("/RACE/Release")
	if len(entries) != 1 || entries[0].Name != "file.r00" {
		t.Fatalf("live payload missing from listing: %+v", entries)
	}
	pu, _ := b.pendingUploadForPath(p)
	pu.started = time.Now().Add(-11 * time.Minute)
	b.pendingUploads.Store(p, pu)
	if !b.FileExists(p) {
		t.Fatal("long-running upload expired before the transfer timeout")
	}
	b.clearPendingUpload(p)
	if b.FileExists(p) || b.GetFileSize(p) >= 0 {
		t.Fatal("failed/cleared upload left a ghost file")
	}
}
