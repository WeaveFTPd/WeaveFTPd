package slave

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaveftpd/internal/protocol"
)

// Exercise actual socket EOF/reset behavior and the receiving slave's cleanup.
// A net.Pipe cannot distinguish a failed send from a successful TCP FIN.
func TestFollowedUploadFailureDoesNotCommitPartialFile(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	defer certServer.Close()
	for _, version := range []uint16{0, tls.VersionTLS12, tls.VersionTLS13} {
		for _, clientMode := range []bool{false, true} {
			if version == 0 && clientMode {
				continue
			}
			for _, outcome := range []string{"failure", "resume-failure", "abort", "resume-abort", "success"} {
				t.Run(fmt.Sprintf("%d/client=%v/%s", version, clientMode, outcome), func(t *testing.T) {
					sourceDir, destDir := t.TempDir(), t.TempDir()
					makeSlave := func(root string) *Slave {
						a, b := net.Pipe()
						t.Cleanup(func() { a.Close(); b.Close() })
						go io.Copy(io.Discard, b)
						return &Slave{roots: []MountedRoot{{Path: root, MountPath: "/"}}, stream: protocol.NewObjectStream(a)}
					}
					source, dest := makeSlave(sourceDir), makeSlave(destDir)
					payload := bytes.Repeat([]byte("partial JPEG without an SFV\n"), 8192)
					if err := os.WriteFile(filepath.Join(sourceDir, "cover.jpg"), payload, 0644); err != nil {
						t.Fatal(err)
					}
					var offset int64
					if strings.HasPrefix(outcome, "resume-") {
						offset = 123
						if err := os.WriteFile(filepath.Join(destDir, "cover.jpg"), payload[:offset], 0644); err != nil {
							t.Fatal(err)
						}
					}
					upload := NewTransfer(nil, nil, 1, source, false, false)
					upload.SetPath("/cover.jpg")
					upload.direction = TransferReceiving
					source.registerUpload(upload)
					defer source.unregisterUpload(upload)

					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					sendConn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer sendConn.Close()
					receiveConn, err := listener.Accept()
					if err != nil {
						t.Fatal(err)
					}
					defer receiveConn.Close()
					_ = sendConn.SetDeadline(time.Now().Add(5 * time.Second))
					_ = receiveConn.SetDeadline(time.Now().Add(5 * time.Second))
					if version != 0 {
						pool := x509.NewCertPool()
						pool.AddCert(certServer.Certificate())
						clientCfg := &tls.Config{RootCAs: pool, ServerName: certServer.Certificate().DNSNames[0], MinVersion: version, MaxVersion: version}
						serverCfg := certServer.TLS.Clone()
						serverCfg.MinVersion = version
						serverCfg.MaxVersion = version
						if clientMode {
							sendConn = tls.Client(sendConn, clientCfg)
							receiveConn = tls.Server(receiveConn, serverCfg)
						} else {
							sendConn = tls.Server(sendConn, serverCfg)
							receiveConn = tls.Client(receiveConn, clientCfg)
						}
						handshake := make(chan error, 1)
						go func() { handshake <- receiveConn.(*tls.Conn).Handshake() }()
						if err := sendConn.(*tls.Conn).Handshake(); err != nil {
							t.Fatal(err)
						}
						if err := <-handshake; err != nil {
							t.Fatal(err)
						}
					}
					sender := NewTransfer(nil, sendConn, 2, source, version != 0, clientMode)
					receiver := NewTransfer(nil, receiveConn, 3, dest, version != 0, !clientMode)
					receiver.SetPath("/cover.jpg")
					sent, received := make(chan protocol.TransferStatus, 1), make(chan protocol.TransferStatus, 1)
					go func() { received <- receiver.ReceiveFile("/cover.jpg", offset, "") }()
					go func() { sent <- sender.SendFile("/cover.jpg", offset, "") }()
					deadline := time.Now().Add(3 * time.Second)
					for receiver.transferred.Load() != int64(len(payload))-offset {
						if time.Now().After(deadline) {
							t.Fatal("receiver did not consume initial bytes")
						}
						time.Sleep(time.Millisecond)
					}
					aborted := strings.HasSuffix(outcome, "abort")
					if aborted {
						sender.Abort("test cancellation")
					} else if outcome != "success" {
						upload.errorStatus("upstream connection reset")
					}
					upload.mu.Lock()
					upload.finished = time.Now()
					upload.mu.Unlock()
					var sendStatus, receiveStatus protocol.TransferStatus
					select {
					case sendStatus = <-sent:
					case <-time.After(3 * time.Second):
						t.Fatal("sender stuck")
					}
					select {
					case receiveStatus = <-received:
					case <-time.After(3 * time.Second):
						t.Fatal("receiver stuck")
					}
					if outcome == "success" {
						if sendStatus.Error != "" || receiveStatus.Error != "" {
							t.Fatalf("successful upload failed: send=%+v receive=%+v", sendStatus, receiveStatus)
						}
						got, err := os.ReadFile(filepath.Join(destDir, "cover.jpg"))
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("successful file truncated: %d err=%v", len(got), err)
						}
						return
					}
					if !aborted && !strings.Contains(sendStatus.Error, "source upload failed") {
						t.Fatalf("source failure lost: %+v", sendStatus)
					}
					if aborted && sendStatus.Error == "" {
						t.Fatalf("cancelled sender reported success: %+v", sendStatus)
					}
					if receiveStatus.Error == "" {
						t.Errorf("destination accepted failed source as a complete file: %+v", receiveStatus)
					}
					got, err := os.ReadFile(filepath.Join(destDir, "cover.jpg"))
					if offset == 0 {
						if !os.IsNotExist(err) {
							t.Errorf("failed JPEG remains: %d bytes err=%v", len(got), err)
						}
					} else if err != nil || !bytes.Equal(got, payload[:offset]) {
						t.Errorf("resume failure did not preserve original prefix: %d bytes err=%v", len(got), err)
					}
				})
			}
		}
	}
}
