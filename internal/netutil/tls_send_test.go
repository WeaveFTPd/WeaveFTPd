package netutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFinishDataSendTLSClient(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	defer certServer.Close()
	cert := certServer.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, hold := range []bool{false, true} {
			t.Run(tls.VersionName(version)+map[bool]string{false: "/close", true: "/peer-waits-for-reply"}[hold], func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				payload := bytes.Repeat([]byte("TLS session tickets must not truncate a file\n"), 6000)
				type result struct {
					data []byte
					err  error
				}
				received := make(chan result, 1)
				release := make(chan struct{})
				defer close(release)
				go func() {
					raw, err := listener.Accept()
					if err != nil {
						received <- result{err: err}
						return
					}
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
					cfg := certServer.TLS.Clone()
					cfg.MinVersion = version
					cfg.MaxVersion = version
					peer := tls.Server(raw, cfg)
					data, err := io.ReadAll(peer)
					received <- result{data, err}
					if hold {
						<-release
					}
					_ = peer.Close()
				}()
				raw, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				client := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: cert.DNSNames[0], MinVersion: version, MaxVersion: version, ClientSessionCache: tls.NewLRUClientSessionCache(1)})
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				if err := FinishDataSend(client, true); err != nil {
					t.Fatal(err)
				}
				if time.Since(start) > tlsSendCloseGrace+time.Second {
					t.Fatal("peer held sender open beyond close grace")
				}
				select {
				case got := <-received:
					if got.err != nil || !bytes.Equal(got.data, payload) {
						t.Fatalf("received %d/%d bytes, err=%v", len(got.data), len(payload), got.err)
					}
				case <-time.After(time.Second):
					t.Fatal("receiver did not see complete TLS EOF")
				}
			})
		}
	}
}
