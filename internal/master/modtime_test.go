package master

import (
	"path/filepath"
	"testing"
	"time"
)

func TestVFSModTimePersistsWithoutChangingTransferMetadata(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.AddFile("/iNFO/Racetrade/RaceTrade.exe", VFSFile{Size: 123, Owner: "uploader", SlaveName: "slave1", XferTime: 500, Checksum: 42})
	before := vfs.GetFile("/iNFO/Racetrade/RaceTrade.exe")
	stamp := time.Date(2026, 11, 20, 23, 0, 9, 0, time.UTC)
	vfs.SetModTime("/iNFO/Racetrade/RaceTrade.exe", stamp)
	if before.LastModified == stamp.Unix() {
		t.Fatal("mutated a published VFS entry")
	}
	state := filepath.Join(t.TempDir(), "vfs.gob")
	if err := vfs.SaveToDisk(state); err != nil {
		t.Fatal(err)
	}
	loaded := NewVirtualFileSystem()
	if err := loaded.LoadFromDisk(state); err != nil {
		t.Fatal(err)
	}
	file := loaded.GetFile("/iNFO/Racetrade/RaceTrade.exe")
	if file == nil || file.LastModified != stamp.Unix() || file.Size != 123 || file.Owner != "uploader" || file.XferTime != 500 || file.Checksum != 42 {
		t.Fatalf("persisted file: %+v", file)
	}
}
