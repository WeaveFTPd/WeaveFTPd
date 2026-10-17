package core

import "testing"

type listingStatsTestBridge struct {
	MasterBridge
	snapshotCalls int
}

func (b *listingStatsTestBridge) GetVFSRaceStats(string) ([]VFSRaceUser, []VFSRaceGroup, int64, int, int) {
	b.snapshotCalls++
	return nil, nil, 1024, 1, 2
}

func (b *listingStatsTestBridge) GetVFSRaceStatsFresh(string) ([]VFSRaceUser, []VFSRaceGroup, int64, int, int) {
	panic("listing requested fresh slave statistics")
}

func TestListingRaceStatsUsesSnapshot(t *testing.T) {
	b := &listingStatsTestBridge{}
	_, _, bytes, present, total := raceStatsForDir(b, &Config{}, "/test")
	if b.snapshotCalls != 1 || bytes != 1024 || present != 1 || total != 2 {
		t.Fatalf("unexpected listing snapshot: calls=%d bytes=%d present=%d total=%d", b.snapshotCalls, bytes, present, total)
	}
}
