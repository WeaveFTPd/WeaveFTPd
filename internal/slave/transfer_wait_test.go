package slave

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaveftpd/internal/protocol"
)

// Use the real receiver, including its own idle timeout. Small metadata files
// may have all their bytes on disk while the source keeps its data socket open
// for more than 20 seconds before sending EOF (observed with production FXP).
func TestSendFileWaitsForSourceEOFAndIdleFailure(t *testing.T) {
	for _, tc := range []struct {
		name            string
		encrypted, idle bool
	}{
		{"plain-delayed-eof", false, false},
		{"tls-buffer-delayed-eof", true, false},
		{"source-idle-fails-followers", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			control, monitor := net.Pipe()
			defer control.Close()
			defer monitor.Close()
			go io.Copy(io.Discard, monitor)
			s := &Slave{roots: []MountedRoot{{Path: dir, MountPath: "/"}}, stream: protocol.NewObjectStream(control)}
			server, source := net.Pipe()
			defer source.Close()
			upload := NewTransfer(nil, server, 1, s, false, false)
			upload.SetPath("/metadata.sfv")
			received := make(chan protocol.TransferStatus, 1)
			go func() { received <- upload.ReceiveFile("/metadata.sfv", 0, "") }()
			payload := bytes.Repeat([]byte("file.r00 12345678\n"), 70)
			if _, err := source.Write(payload); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				info, err := os.Stat(filepath.Join(dir, "metadata.sfv"))
				if err == nil && info.Size() == int64(len(payload)) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("source did not write metadata")
				}
				time.Sleep(time.Millisecond)
			}
			a, b := net.Pipe()
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(40 * time.Second))
			send := NewTransfer(nil, a, 2, s, tc.encrypted, false)
			status := make(chan protocol.TransferStatus, 1)
			go func() { status <- send.SendFile("/metadata.sfv", 0, "") }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(b, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("metadata bytes changed")
			}
			type readResult struct {
				data []byte
				err  error
			}
			readDone := make(chan readResult, 1)
			go func() { data, err := io.ReadAll(b); readDone <- readResult{data, err} }()
			if !tc.idle {
				select {
				case st := <-status:
					t.Fatalf("follower ended before source EOF: %+v", st)
				case <-time.After(21 * time.Second):
				}
				source.Close()
			}
			select {
			case st := <-status:
				if tc.idle {
					if !strings.Contains(st.Error, "source upload failed: receive idle timeout") {
						t.Fatalf("source idle failure not propagated: %+v", st)
					}
				} else if st.Error != "" || st.Transferred != int64(len(payload)) {
					t.Fatalf("valid source failed: %+v", st)
				}
			case <-time.After(35 * time.Second):
				t.Fatal("follower was not released")
			}
			select {
			case st := <-received:
				if tc.idle && !strings.Contains(st.Error, "receive idle timeout") {
					t.Fatalf("receiver did not enforce its idle bound: %+v", st)
				}
				if !tc.idle && st.Error != "" {
					t.Fatalf("receiver failed: %+v", st)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("source receiver remained active")
			}
			select {
			case rest := <-readDone:
				if len(rest.data) != 0 || rest.err != nil {
					t.Fatalf("unexpected tail: %+v", rest)
				}
			case <-time.After(time.Second):
				t.Fatal("data connection remained open")
			}
		})
	}
}
