package master

import (
	"path/filepath"
	"testing"
)

func TestVirtualLinkSurvivesSlaveScan(t *testing.T) {
	v := NewVirtualFileSystem()
	v.AddFile("/MP3/1117", VFSFile{IsDir: true, SlaveName: "LOCAL"})
	v.AddFile("/!Today_MP3", VFSFile{IsDir: true, SlaveName: "LOCAL"})
	v.AddFile("/!Today_MP3/old/file.mp3", VFSFile{Size: 123, SlaveName: "LOCAL"})
	v.AddVirtualSymlink("/!Today_MP3", "/MP3/1117")
	if v.GetFile("/!Today_MP3/old/file.mp3") != nil {
		t.Fatal("shadow file remained indexed")
	}
	for _, p := range []string{"/!Today_MP3", "/!Today_MP3/new", "/!Today_MP3/new/file.mp3"} {
		v.AddFile(p, VFSFile{IsDir: true, SlaveName: "LOCAL"})
	}
	if got := v.ResolvePath("/!Today_MP3/new/file.mp3"); got != "/MP3/1117/new/file.mp3" {
		t.Fatal(got)
	}
	if v.GetFile("/!Today_MP3/new") != nil {
		t.Fatal("scan recreated shadow directory")
	}
	v.MarkAllUnseen("LOCAL")
	v.PurgeUnseen("LOCAL")
	if f := v.GetFile("/!Today_MP3"); f == nil || !f.VirtualOnly || !f.IsSymlink {
		t.Fatalf("lost virtual link: %+v", f)
	}
	v.AddVirtualSymlink("/!Today_MP3", "/MP3/1118")
	if got := v.ResolvePath("/!Today_MP3/new/file.mp3"); got != "/MP3/1118/new/file.mp3" {
		t.Fatal(got)
	}
}

func TestPhysicalSymlinkStillRefreshesFromSlave(t *testing.T) {
	v := NewVirtualFileSystem()
	v.AddSymlink("/physical", "/old")
	v.AddFile("/physical", VFSFile{IsSymlink: true, LinkTarget: "/new", SlaveName: "LOCAL"})
	if got := v.ResolvePath("/physical/file"); got != "/new/file" {
		t.Fatal(got)
	}
}

func TestVirtualLinkOwnershipPersists(t *testing.T) {
	v := NewVirtualFileSystem()
	v.AddVirtualSymlink("/!Today_EBOOKS", "/EBOOKS/1117")
	p := filepath.Join(t.TempDir(), "vfs.gob")
	if err := v.SaveToDisk(p); err != nil {
		t.Fatal(err)
	}
	restored := NewVirtualFileSystem()
	if err := restored.LoadFromDisk(p); err != nil {
		t.Fatal(err)
	}
	restored.AddFile("/!Today_EBOOKS", VFSFile{IsDir: true, SlaveName: "LOCAL"})
	if got := restored.ResolvePath("/!Today_EBOOKS/release/book.zip"); got != "/EBOOKS/1117/release/book.zip" {
		t.Fatal(got)
	}
}

func TestVirtualLinkRenameDestination(t *testing.T) {
	sm := NewSlaveManager("127.0.0.1", 1099, false, "", "", 60)
	b := &Bridge{sm: sm}
	v := sm.GetVFS()
	v.AddVirtualSymlink("/!Today_MP3", "/MP3/1117")
	v.AddSymlink("/source", "/FLAC/1117")
	if err := b.RenameFile("/source", "/", "!Today_MP3"); err == nil {
		t.Fatal("allowed replacing virtual link")
	}
	if v.GetFile("/source") == nil {
		t.Fatal("source changed on rejected rename")
	}
	if err := b.RenameFile("/source", "/!Today_MP3", "renamed"); err != nil {
		t.Fatal(err)
	}
	if v.GetFile("/MP3/1117/renamed") == nil {
		t.Fatal("rename did not use resolved target directory")
	}
	if v.GetFile("/!Today_MP3/renamed") != nil {
		t.Fatal("rename created a shadow entry")
	}
}
