package core

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveDownloadReservationAndUploadOutcome(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "abort"}[success], func(t *testing.T) {
			p := "/live/" + t.Name()
			if !reserveUploadPath(p) {
				t.Fatal("reserve upload")
			}
			defer releaseUploadPath(p)
			if _, ok := reserveDownloadPathFollowing(p, false); ok {
				t.Fatal("disabled policy accepted live download")
			}
			state, ok := reserveDownloadPathFollowing(p, true)
			if !ok || state == nil {
				t.Fatal("enabled policy rejected live download")
			}
			defer releaseDownloadPath(p)
			if reserveUploadPath(p) {
				t.Fatal("second writer accepted")
			}
			if success {
				completeUploadPath(p)
			}
			releaseUploadPath(p)
			if err := state.wait(); (err == nil) != success {
				t.Fatalf("completion = %v", err)
			}
			if reserveUploadPath(p) {
				t.Fatal("overwrite accepted while reader remains")
			}
			releaseDownloadPath(p)
			if !reserveUploadPath(p) {
				t.Fatal("writer rejected after readers left")
			}
			// A new generation must not overwrite the old result.
			releaseUploadPath(p)
			if err := state.wait(); (err == nil) != success {
				t.Fatalf("old completion changed: %v", err)
			}
		})
	}
}

func TestGrowingUploadReaderFollowsAndFailsAbortedSource(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "abort"}[success], func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "source")
			writer, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if _, err = writer.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			reader, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			state := &uploadPathState{done: make(chan struct{})}
			r := &growingUploadReader{file: reader, upload: state, lastProgress: time.Now()}
			first := make([]byte, 5)
			if _, err = io.ReadFull(r, first); err != nil {
				t.Fatal(err)
			}
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { b, e := io.ReadAll(r); done <- result{b, e} }()
			select {
			case got := <-done:
				t.Fatalf("premature EOF: %+v", got)
			case <-time.After(120 * time.Millisecond):
			}
			// Final write and completion are deliberately adjacent to exercise
			// the race between EOF and upload completion.
			tail := bytes.Repeat([]byte("tail"), 16384)
			if _, err = writer.Write(tail); err != nil {
				t.Fatal(err)
			}
			state.finish(success)
			select {
			case got := <-done:
				if success && (got.err != nil || !bytes.Equal(got.data, tail)) {
					t.Fatalf("truncated successful follower: %d, %v", len(got.data), got.err)
				}
				if !success && got.err == nil {
					t.Fatal("aborted upload reported EOF success")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("follower hung")
			}
		})
	}
}

func TestDLIncompleteConfigAndRehash(t *testing.T) {
	base := `mode: master
listen_port: 21
storage_path: ./site
acl_base_path: /
tls_enabled: false
master:
  listen_host: 127.0.0.1
  control_port: 1099
`
	for _, tc := range []struct {
		setting string
		want    bool
	}{{"", true}, {"dl_incomplete: true\n", true}, {"dl_incomplete: false\n", false}} {
		t.Run(strings.TrimSpace(tc.setting), func(t *testing.T) {
			p := writeConfigFixture(t, base+tc.setting)
			cfg, err := LoadConfig(p)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DLIncomplete != tc.want {
				t.Fatalf("setting = %v, want %v", cfg.DLIncomplete, tc.want)
			}
			if err = os.WriteFile(p, []byte(base+"dl_incomplete: false\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = cfg.Rehash(); err != nil {
				t.Fatal(err)
			}
			if cfg.DLIncomplete {
				t.Fatal("rehash did not disable live downloads")
			}
			if err = os.WriteFile(p, []byte(base+"dl_incomplete: true\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = cfg.Rehash(); err != nil {
				t.Fatal(err)
			}
			if !cfg.DLIncomplete {
				t.Fatal("rehash did not enable live downloads")
			}
		})
	}
}
