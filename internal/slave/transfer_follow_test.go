package slave

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaveftpd/internal/protocol"
)

// Exercise the sendfile and TLS/userspace branches, retained upload outcome,
// final-byte delivery, concurrent readers and REST while the source grows.
func TestSendFileFollowsGrowingUpload(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, abort := range []bool{false, true} {
			name := map[bool]string{false: "plain", true: "tls-buffer"}[encrypted] + map[bool]string{false: "-success", true: "-abort"}[abort]
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				p := filepath.Join(dir, "live.bin")
				f, err := os.Create(p)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				first := bytes.Repeat([]byte("first"), 1024)
				if _, err = f.Write(first); err != nil {
					t.Fatal(err)
				}
				s := &Slave{roots: []MountedRoot{{Path: dir, MountPath: "/"}}}
				upload := NewTransfer(nil, nil, 1, s, false, false)
				upload.SetPath("/live.bin")
				upload.direction = TransferReceiving
				s.registerUpload(upload)
				defer s.unregisterUpload(upload)
				type follower struct {
					conn    net.Conn
					status  chan protocol.TransferStatus
					offset  int64
					initial []byte
				}
				readers := make([]follower, 2)
				for i := range readers {
					a, b := net.Pipe()
					defer b.Close()
					_ = b.SetDeadline(time.Now().Add(5 * time.Second))
					x := NewTransfer(nil, a, int32(i+2), s, encrypted, false)
					offset := int64(i * 123)
					done := make(chan protocol.TransferStatus, 1)
					go func() { done <- x.SendFile("/live.bin", offset, "") }()
					prefix := make([]byte, int64(len(first))-offset)
					if _, err = io.ReadFull(b, prefix); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(prefix, first[offset:]) {
						t.Fatal("wrong initial bytes")
					}
					readers[i] = follower{b, done, offset, prefix}
				}
				for _, r := range readers {
					select {
					case st := <-r.status:
						t.Fatalf("premature completion %+v", st)
					default:
					}
				}
				tail := bytes.Repeat([]byte("tail"), 8192)
				if _, err = f.Write(tail); err != nil {
					t.Fatal(err)
				}
				if abort {
					upload.errorStatus("simulated disk failure")
				}
				upload.mu.Lock()
				upload.finished = time.Now()
				upload.mu.Unlock()
				// Mimic removal from the live index before the follower wakes.
				s.unregisterUpload(upload)
				for _, r := range readers {
					data, readErr := io.ReadAll(r.conn)
					if readErr != nil {
						t.Fatal(readErr)
					}
					select {
					case st := <-r.status:
						if abort && st.Error == "" {
							t.Fatal("failed source reported success")
						}
						if !abort && (st.Error != "" || !bytes.Equal(data, tail) || st.Transferred != int64(len(first)+len(tail))-r.offset) {
							t.Fatalf("truncated or failed: len=%d status=%+v", len(data), st)
						}
					case <-time.After(time.Second):
						t.Fatal("follower did not finish")
					}
				}
			})
		}
	}
}
