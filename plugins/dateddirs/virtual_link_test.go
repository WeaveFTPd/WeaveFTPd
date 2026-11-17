package dateddirs

import (
	"testing"
	"time"
	"weaveftpd/internal/plugin"
)

type existingLinkBridge struct {
	plugin.MasterBridge
	calls int
}

func (b *existingLinkBridge) FileExists(string) bool { return true }
func (b *existingLinkBridge) PluginListDir(string) []plugin.FileEntry {
	return []plugin.FileEntry{{Name: "!Today_MP3", IsDir: true, IsSymlink: true, LinkTarget: "/MP3/1117"}}
}
func (b *existingLinkBridge) VFSSymlink(link, target string) error { b.calls++; return nil }

func TestDatedDirsRegistersRestoredVirtualLink(t *testing.T) {
	b := &existingLinkBridge{}
	h := &Handler{svc: &plugin.Services{Bridge: b}, sections: []string{"MP3"}, format: "MMDD", todaySymlink: true, symlinkPrefix: "!Today_"}
	h.apply(time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC))
	h.apply(time.Date(2026, 11, 17, 12, 1, 0, 0, time.UTC))
	if b.calls != 2 {
		t.Fatalf("virtual ownership registered %d times, want 2", b.calls)
	}
}

func TestDatedDirsRejectsUnresolvedAliasWrites(t *testing.T) {
	h := &Handler{sections: []string{"MP3", "EBOOKS"}, todaySymlink: true, symlinkPrefix: "!Today_"}
	for _, p := range []string{"/!Today_MP3", "/!Today_MP3/release/file.mp3", "/!today_ebooks/release/book.zip"} {
		if h.ValidateMKDir(nil, p) == nil || h.ValidateUpload(nil, p) == nil {
			t.Errorf("allowed unresolved %s", p)
		}
	}
	for _, p := range []string{"/MP3/1117/release/file.mp3", "/EBOOKS/1117/book.zip", "/!Today_OTHER/release", "/!Today_MP3-other"} {
		if err := h.ValidateUpload(nil, p); err != nil {
			t.Fatal(err)
		}
	}
	h.todaySymlink = false
	if err := h.ValidateUpload(nil, "/!Today_MP3/release"); err != nil {
		t.Fatal(err)
	}
}
