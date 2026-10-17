package master

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"weaveftpd/internal/core"
	"weaveftpd/internal/protocol"
)

func TestListingRepairDuringRaceDBWrite(t *testing.T) {
	rdb, err := NewRaceDB(filepath.Join(t.TempDir(), "race #1.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	const dir = "/test/listing-writer"
	const file = dir + "/file.zip"
	zeroSizeRepairCache.Delete(dir)
	t.Cleanup(func() { zeroSizeRepairCache.Delete(dir) })
	if err := rdb.RecordUpload(file, "racer", "group", 1024, 1000, 123); err != nil {
		t.Fatal(err)
	}
	tx, err := rdb.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE release_files SET size_bytes = 2048"); err != nil {
		t.Fatal(err)
	}
	sm := NewSlaveManager("127.0.0.1", 1099, false, "", "", 60)
	sm.GetVFS().AddFile(file, VFSFile{Path: file, SlaveName: "LOCAL"})
	b := &Bridge{sm: sm, raceDB: rdb}
	done := make(chan []core.MasterFileEntry, 1)
	go func() { done <- b.ListDir(dir) }()
	select {
	case entries := <-done:
		if len(entries) != 1 || entries[0].Size != 1024 {
			t.Fatalf("want committed size during writer transaction, got %+v", entries)
		}
	case <-time.After(time.Second):
		t.Fatal("listing waited for the writer connection")
	}
}

func TestListingReaderDeadlineAndRecovery(t *testing.T) {
	rdb, err := NewRaceDB(filepath.Join(t.TempDir(), "race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	conn, err := rdb.listingDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_, err = rdb.VerifiedPresentFiles("/test")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline while reader occupied, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("reader wait took %s", elapsed)
	}
	conn.Close()
	if _, err := rdb.VerifiedPresentFiles("/test"); err != nil {
		t.Fatalf("reader failed to recover: %v", err)
	}
	if _, err := rdb.listingDB.Exec("DELETE FROM releases"); err == nil {
		t.Fatal("listing reader allowed a write")
	}
}

func TestListingReaderDoesNotWaitForSQLiteLock(t *testing.T) {
	rdb, err := NewRaceDB(filepath.Join(t.TempDir(), "race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	// Force a real SQLite read lock (ordinary WAL writers do not block reads),
	// also exercising DSN settings on replacement reader connections.
	rdb.listingDB.SetMaxIdleConns(0)
	if _, err := rdb.db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatal(err)
	}
	if _, err := rdb.db.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	defer rdb.db.Exec("ROLLBACK")
	start := time.Now()
	if _, err := rdb.VerifiedPresentFiles("/test"); err == nil {
		t.Fatal("expected a lock error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("SQLite lock wait took %s", elapsed)
	}
}

func TestListingStatsNeverWaitForRefreshMutex(t *testing.T) {
	for _, warm := range []bool{false, true} {
		b := &Bridge{sm: NewSlaveManager("127.0.0.1", 1099, false, "", "", 60)}
		if warm {
			b.liveTransferStatsCache = []core.LiveTransferStat{{SlaveName: "test"}}
			b.liveTransferStatsAt = time.Now().Add(-time.Hour)
		}
		b.liveTransferStatsMu.Lock()
		done := make(chan []core.LiveTransferStat, 1)
		go func() { done <- b.GetLiveTransferStats() }()
		select {
		case got := <-done:
			b.liveTransferStatsMu.Unlock()
			if warm && (len(got) != 1 || got[0].SlaveName != "test") {
				t.Fatalf("lost cached snapshot: %+v", got)
			}
		case <-time.After(time.Second):
			b.liveTransferStatsMu.Unlock()
			t.Fatal("listing waited for refresh mutex")
		}
	}
}

func TestListingStatsRefreshInBackground(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failed-retains-snapshot"}[fail], func(t *testing.T) {
			masterConn, slaveConn := net.Pipe()
			defer masterConn.Close()
			defer slaveConn.Close()
			rs := NewRemoteSlave("test", masterConn, protocol.NewObjectStream(masterConn), time.Second, nil)
			sm := NewSlaveManager("127.0.0.1", 1099, false, "", "", 60)
			sm.slaves["test"] = rs
			b := &Bridge{sm: sm, liveTransferStatsAt: time.Now().Add(-time.Hour),
				liveTransferStatsCache: []core.LiveTransferStat{{SlaveName: "test", Path: "/active.zip", Direction: "upload"}}}
			request := make(chan *protocol.AsyncCommand, 1)
			go func() {
				obj, err := protocol.NewObjectStream(slaveConn).ReadObject()
				if err == nil {
					request <- obj.(*protocol.AsyncCommand)
				}
			}()
			start := time.Now()
			got := b.GetLiveTransferStats()
			if time.Since(start) > time.Second || len(got) != 1 {
				t.Fatalf("listing failed to return old snapshot immediately: %+v", got)
			}
			var cmd *protocol.AsyncCommand
			select {
			case cmd = <-request:
			case <-time.After(time.Second):
				t.Fatal("background refresh did not start")
			}
			if got := b.GetLiveTransferStats(); len(got) != 1 {
				t.Fatal("snapshot unavailable while slave reply is pending")
			}
			if fail {
				rs.routeResponse(cmd.Index, &protocol.AsyncResponseError{Index: cmd.Index, Message: "test failure"})
			} else {
				rs.routeResponse(cmd.Index, &protocol.AsyncResponseTransferStats{Index: cmd.Index})
			}
			done := make(chan struct{})
			go func() { b.liveTransferStatsMu.Lock(); b.liveTransferStatsMu.Unlock(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("background refresh did not finish")
			}
			got = b.GetLiveTransferStats()
			if fail && len(got) != 1 || !fail && len(got) != 0 {
				t.Fatalf("incorrect snapshot after refresh: %+v", got)
			}
		})
	}
}
