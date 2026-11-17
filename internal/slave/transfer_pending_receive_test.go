package slave

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"weaveftpd/internal/protocol"
)

func TestRetrieveWaitsForPendingReceive(t *testing.T) {
	s := &Slave{roots: []MountedRoot{{Path: t.TempDir(), MountPath: "/"}}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	receive := NewTransfer(l, nil, 1, s, false, false)
	receive.SetPath("/file.sfv")
	s.transfers.Store(int32(1), receive)
	s.registerUpload(receive) // Same ordering as handleReceive before its ACK.
	done := make(chan protocol.TransferStatus, 1)
	go func() { done <- receive.ReceiveFile("/file.sfv", 0, "") }()
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(5 * time.Second))
	send := NewTransfer(nil, a, 2, s, false, false)
	sent := make(chan protocol.TransferStatus, 1)
	go func() { sent <- send.SendFile("/file.sfv", 0, "") }()
	select {
	case st := <-sent:
		t.Fatalf("download failed before source connected: %+v", st)
	case <-time.After(150 * time.Millisecond):
	}
	source, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := source.Write([]byte("file.rar 12345678\n")); err != nil {
		source.Close()
		t.Fatal(err)
	}
	source.Close()
	data, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "file.rar 12345678\n" {
		t.Fatalf("payload=%q", data)
	}
	for _, ch := range []chan protocol.TransferStatus{done, sent} {
		select {
		case st := <-ch:
			if st.Error != "" {
				t.Fatal(st.Error)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("transfer did not stop")
		}
	}
}

func TestPendingReceiveWaitAbortsAndTimesOut(t *testing.T) {
	for _, tc := range []string{"source-abort", "download-abort", "timeout"} {
		t.Run(tc, func(t *testing.T) {
			s := &Slave{timeout: time.Second}
			source := NewTransfer(nil, nil, 1, s, false, false)
			send := NewTransfer(nil, nil, 2, s, false, false)
			want := "source upload setup timed out"
			switch tc {
			case "source-abort":
				source.Abort("source cancelled")
				want = "source upload failed"
			case "download-abort":
				send.Abort("reader cancelled")
				want = "aborted: reader cancelled"
			}
			err := send.waitForUploadReady(source)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err=%v want %s", err, want)
			}
		})
	}
}
