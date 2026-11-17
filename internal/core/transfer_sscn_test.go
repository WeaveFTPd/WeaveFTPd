package core

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPassiveSSCNFileTLSRoles(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	cert := server.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	for _, tc := range []struct {
		name                                 string
		sscn, active, cpsv, file, peerServer bool
	}{
		{"passive-file-server", false, false, false, true, false},
		{"passive-file-client", true, false, false, true, true},
		{"active-file-client", true, true, false, true, true},
		{"active-file-server", false, true, false, true, false},
		{"cpsv-file-client", false, false, true, true, true},
		{"listing-after-sscn-on", true, false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(3 * time.Second))
			cfg := server.TLS.Clone()
			cfg.SessionTicketsDisabled = true
			var peer *tls.Conn
			if tc.peerServer {
				peer = tls.Server(b, cfg.Clone())
			} else {
				peer = tls.Client(b, &tls.Config{RootCAs: pool, ServerName: cert.DNSNames[0]})
			}
			done := make(chan error, 1)
			go func() { done <- peer.Handshake() }()
			s := &Session{Config: &Config{}, DataTLS: true, SSCN: tc.sscn, lastDataConnActive: tc.active, nextDataTLSClientMode: tc.cpsv}
			var err error
			if tc.file {
				_, err = s.upgradeFileDataTLS(a, cfg)
			} else {
				_, err = s.upgradeDataTLS(a, cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if s.SSCN != tc.sscn || s.nextDataTLSClientMode {
				t.Fatal("persistent SSCN or one-shot CPSV state changed incorrectly")
			}
		})
	}
}

func TestPassiveSSCNFileClearData(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := &Session{Config: &Config{}, SSCN: true}
	got, err := s.upgradeFileDataTLS(a, nil)
	if err != nil || got != a || s.nextDataTLSClientMode || !s.SSCN {
		t.Fatal("PROT C unexpectedly negotiated TLS or changed SSCN state")
	}
}
