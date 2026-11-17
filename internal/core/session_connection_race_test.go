package core

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"weaveftpd/internal/user"
)

func TestSessionSnapshotKeepsRegisteredRemote(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{Conn: server}
	id := registerSession(s)
	defer unregisterSession(id)
	if s.ID != id {
		t.Fatal("session ID must be set before publication")
	}
	s.Conn = nil
	for _, snap := range listActiveSessions() {
		if snap.ID == id {
			if snap.Remote != server.RemoteAddr().String() {
				t.Fatalf("registered remote lost: %q", snap.Remote)
			}
			return
		}
	}
	t.Fatal("registered session missing")
}

func TestSessionRegistryConcurrentTLSUpgrade(t *testing.T) {
	for _, kick := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "kick"}[kick], func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			s := &Session{Conn: server, IsLogged: true, User: &user.User{Name: "tls-race-test"}}
			id := registerSession(s)
			defer unregisterSession(id)
			wrapped := tls.Server(server, &tls.Config{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 10000; i++ {
					s.Conn = wrapped
					s.Conn = server
				}
			}()
			for i := 0; i < 100; i++ {
				ListActiveSessionsForPlugins()
				if kick {
					kickActiveUser("tls-race-test")
				} else {
					DisconnectActiveSession(id)
				}
			}
			wg.Wait()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("original control transport was not closed: %v", err)
			}
		})
	}
}
