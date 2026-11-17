package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"weaveftpd/internal/acl"
	"weaveftpd/internal/user"
)

type followerAbortRecorder struct {
	mu      sync.Mutex
	indices []int32
	aborted chan int32
}

type failedFollowerBridge struct {
	MasterBridge
	ready chan struct{}
	abort chan struct{}
	once  sync.Once
}

func (b *failedFollowerBridge) ResolvePath(p string) string { return p }
func (b *failedFollowerBridge) GetFileSize(string) int64    { return 200000000 }
func (b *failedFollowerBridge) AbortTransfer(_ string, index int32, _ string) bool {
	if index != 123 {
		panic("cancelled unrelated transfer")
	}
	b.once.Do(func() { close(b.abort) })
	return true
}
func (b *failedFollowerBridge) SlaveConnectAndSend(_, _, _, _ string, _ int64, _, _ bool, _ byte, ready TransferReadyFunc) (uint32, int64, error) {
	ready("storage", 123)
	return b.send()
}
func (b *failedFollowerBridge) SlaveSendPassthrough(_ string, _ int32, _, _, _ string, _ int64, _ byte) (uint32, int64, error) {
	return b.send()
}
func (b *failedFollowerBridge) send() (uint32, int64, error) {
	close(b.ready)
	<-b.abort
	return 0, 0, fmt.Errorf("source upload failed")
}

func (b *failedFollowerBridge) DownloadFileTracked(_ string, _ net.Conn, _, _ string, _ int64, _ byte, ready TransferReadyFunc) (uint32, error) {
	ready("storage", 123)
	checksum, _, err := b.send()
	return checksum, err
}

func TestRETRFailedSourceReleasesBeforeBlockedControlReply(t *testing.T) {
	for _, mode := range []string{"PORT", "PASV", "PROXY"} {
		t.Run(mode, func(t *testing.T) {
			p := "/live/" + t.Name() + "/file.rar"
			if !reserveUploadPath(p) {
				t.Fatal("upload reservation")
			}
			defer releaseUploadPath(p)
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			server.SetDeadline(time.Now().Add(3 * time.Second))
			client.SetDeadline(time.Now().Add(3 * time.Second))
			bridge := &failedFollowerBridge{ready: make(chan struct{}), abort: make(chan struct{})}
			s := &Session{Conn: server, CurrentDir: "/", Config: &Config{Mode: "master", Passthrough: true, DLIncomplete: true, ACLBasePath: "/"},
				MasterManager: bridge, User: &user.User{Name: "reader", Flags: "3"}, IsLogged: true,
				ACLEngine: &acl.Engine{RulesByType: map[string][]acl.Rule{"download": {{Type: "download", Path: "/*", Requirement: &acl.Requirement{Anyone: true}}}}}}
			if mode == "PROXY" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				s.Config.Passthrough = false
				s.ActiveAddr = listener.Addr().String()
				accepted := make(chan struct{})
				go func() {
					conn, err := listener.Accept()
					if err == nil {
						defer conn.Close()
						<-bridge.abort
					}
					close(accepted)
				}()
				defer func() { bridge.once.Do(func() { close(bridge.abort) }); listener.Close(); <-accepted }()
			} else if mode == "PORT" {
				s.ActiveAddr = "127.0.0.1:1234"
			} else {
				s.PassthruSlave = "storage"
				s.PassthruXferIdx = 123
			}
			done := make(chan bool, 1)
			go func() { done <- s.processCommand("RETR", []string{p}, nil) }()
			r := bufio.NewReader(client)
			line, err := r.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "150 ") {
				t.Fatalf("initial reply %q: %v", line, err)
			}
			select {
			case <-bridge.ready:
			case <-time.After(time.Second):
				t.Fatal("transfer not started")
			}
			releaseUploadPath(p) // CRC rejected after the original upload ended
			deadline := time.Now().Add(time.Second)
			for downloadPathReserved(p) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !reserveUploadPath(p) {
				t.Fatal("old RETR blocks reupload while control client is not reading")
			}
			// The old reply may be read much later without touching this generation.
			if _, ok := reserveDownloadPathFollowing(p, true); !ok {
				t.Fatal("replacement follower")
			}
			line, err = r.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "426 ") {
				t.Fatalf("failure reply %q: %v", line, err)
			}
			if <-done {
				t.Fatal("control session disconnected")
			}
			completeUploadPath(p)
			releaseUploadPath(p)
			if reserveUploadPath(p) {
				t.Fatal("late cleanup released replacement reader")
			}
			releaseDownloadPath(p)
		})
	}
}

func TestLocalFollowerBlockedWriteCancelledByFailedUpload(t *testing.T) {
	root := t.TempDir()
	file, err := os.Create(filepath.Join(root, "file.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	p := "/file.rar"
	if !reserveUploadPath(p) {
		t.Fatal("reserve upload")
	}
	defer releaseUploadPath(p)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); peer <- conn }()
	s := &Session{Conn: server, CurrentDir: "/", ActiveAddr: listener.Addr().String(),
		Config: &Config{StoragePath: root, DLIncomplete: true, ACLBasePath: "/"},
		User:   &user.User{Name: "reader", Flags: "3"}, IsLogged: true,
		ACLEngine: &acl.Engine{RulesByType: map[string][]acl.Rule{"download": {{Type: "download", Path: "/*", Requirement: &acl.Requirement{Anyone: true}}}}}}
	done := make(chan bool, 1)
	go func() { done <- s.processCommand("RETR", []string{p}, nil) }()
	r := bufio.NewReader(client)
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "150 ") {
		t.Fatalf("initial reply %q: %v", line, err)
	}
	dataPeer := <-peer
	if dataPeer == nil {
		t.Fatal("data connection missing")
	}
	defer dataPeer.Close()
	dataPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := dataPeer.Read(make([]byte, 1)); err != nil {
		t.Fatalf("download never read the file: %v", err)
	}
	releaseUploadPath(p)
	deadline := time.Now().Add(time.Second)
	for downloadPathReserved(p) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !reserveUploadPath(p) {
		t.Fatal("stalled local downloader blocks reupload")
	}
	line, err = r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "426 ") {
		t.Fatalf("failure reply %q: %v", line, err)
	}
	if <-done {
		t.Fatal("control session disconnected")
	}
}

func (a *followerAbortRecorder) AbortTransfer(_ string, index int32, _ string) bool {
	a.mu.Lock()
	a.indices = append(a.indices, index)
	a.mu.Unlock()
	a.aborted <- index
	return true
}

func TestFailedLiveDownloadUnblocksReupload(t *testing.T) {
	p := "/live/" + t.Name()
	if !reserveUploadPath(p) {
		t.Fatal("upload reservation")
	}
	source, ok := reserveDownloadPathFollowing(p, true)
	if !ok {
		t.Fatal("download reservation")
	}
	d := newLiveDownload(p, source)
	defer d.finish()
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	d.trackConn(server)
	written := make(chan error, 1)
	go func() { _, err := server.Write([]byte("bad upload")); written <- err }()
	releaseUploadPath(p)
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("failed source completed download")
		}
	case <-time.After(time.Second):
		t.Fatal("old downloader still blocked in write")
	}
	// Abort notification alone cannot release a path while SEND may still run.
	if reserveUploadPath(p) {
		t.Fatal("replacement raced active download operation")
	}
	d.finish()
	if !reserveUploadPath(p) {
		t.Fatal("old downloader blocks reupload")
	}
	newSource, ok := reserveDownloadPathFollowing(p, true)
	if !ok || newSource == source {
		t.Fatal("new generation not isolated")
	}
	newDownload := newLiveDownload(p, newSource)
	defer newDownload.finish()
	completeUploadPath(p)
	releaseUploadPath(p)
	d.finish() // delayed old cleanup must not decrement the new reader count
	if reserveUploadPath(p) {
		t.Fatal("old cleanup released new generation's reader")
	}
	newDownload.finish()
	if !reserveUploadPath(p) {
		t.Fatal("new reader not released")
	}
	releaseUploadPath(p)
}

func TestLiveDownloadCancelsLateSlaveOnly(t *testing.T) {
	p := "/live/" + t.Name()
	if !reserveUploadPath(p) {
		t.Fatal("upload reservation")
	}
	source, _ := reserveDownloadPathFollowing(p, true)
	d := newLiveDownload(p, source)
	defer d.finish()
	a := &followerAbortRecorder{aborted: make(chan int32, 4)}
	d.trackSlave(a, "slave", 41)
	releaseUploadPath(p)
	select {
	case index := <-a.aborted:
		if index != 41 {
			t.Fatalf("wrong transfer: %d", index)
		}
	case <-time.After(time.Second):
		t.Fatal("slave not aborted")
	}
	// PORT setup finishing after source failure must not escape cancellation.
	d.trackSlave(a, "slave", 42)
	if index := <-a.aborted; index != 42 {
		t.Fatalf("late transfer: %d", index)
	}
	d.finish()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.indices) != 2 {
		t.Fatalf("unexpected aborts: %v", a.indices)
	}
}

func TestSuccessfulAndOrdinaryDownloadsRemainProtected(t *testing.T) {
	for _, live := range []bool{false, true} {
		name := "ordinary"
		if live {
			name = "live"
		}
		t.Run(name, func(t *testing.T) {
			p := "/live/" + t.Name()
			if live && !reserveUploadPath(p) {
				t.Fatal("upload reservation")
			}
			source, ok := reserveDownloadPathFollowing(p, true)
			if !ok {
				t.Fatal("download reservation")
			}
			d := newLiveDownload(p, source)
			defer d.finish()
			a := &followerAbortRecorder{aborted: make(chan int32, 2)}
			d.trackSlave(a, "slave", 10)
			if live {
				completeUploadPath(p)
				releaseUploadPath(p)
			}
			if reserveUploadPath(p) {
				t.Fatal("normal reader protection lost")
			}
			d.finish()
			select {
			case <-a.aborted:
				t.Fatal("healthy download aborted")
			default:
			}
			if !reserveUploadPath(p) {
				t.Fatal("reader leaked reservation")
			}
			releaseUploadPath(p)
		})
	}
}
