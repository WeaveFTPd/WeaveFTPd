package master

import (
	"fmt"
	"sync"
	"testing"
)

func TestPendingUploadListingIsolationAcrossReleases(t *testing.T) {
	sm := NewSlaveManager("127.0.0.1", 1099, false, "", "", 60)
	b := &Bridge{sm: sm}
	const root = "/XXX-0DAY/1022/Release-A"
	b.notePendingUpload(root+"/own.r03", "LOCAL", "racer", "group", 0)
	for _, dir := range []string{"/XXX-0DAY/1022/Release-B", root + "-suffix", root + "/Sample"} {
		for _, part := range []string{"r03", "r08", "r21", "r31"} {
			b.notePendingUpload(dir+"/foreign."+part, "LOCAL", "racer", "group", 0)
		}
	}
	check := func() {
		t.Helper()
		entries := b.ListDir(root)
		if len(entries) != 1 || entries[0].Name != "own.r03" || entries[0].Size != 1 {
			t.Errorf("foreign pending upload leaked into release listing: %+v", entries)
		}
	}
	check()
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			p := fmt.Sprintf("/XXX-0DAY/1022/Release-%d/changing.r00", worker)
			for i := 0; i < 100; i++ {
				b.notePendingUpload(p, "LOCAL", "racer", "group", 0)
				check()
				b.clearPendingUpload(p)
			}
		}(worker)
	}
	workers.Wait()
	for _, dir := range []string{root + "-missing", "/XXX-0DAY/1022"} {
		if entries := b.ListDir(dir); len(entries) != 0 {
			t.Errorf("non-parent listing %s included pending children: %+v", dir, entries)
		}
	}
	b.clearPendingUpload(root + "/own.r03")
	if entries := b.ListDir(root); len(entries) != 0 {
		t.Fatalf("cleared placeholder persisted: %+v", entries)
	}
}
