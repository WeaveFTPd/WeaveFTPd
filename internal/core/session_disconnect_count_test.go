package core

import (
	"net"
	"testing"
	"weaveftpd/internal/user"
)

// A blocked command handler may not have run its deferred unregister yet.
func TestDisconnectedSessionReleasesLoginSlot(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := &Session{Conn: a, IsLogged: true, User: &user.User{Name: "audit-disconnected", PrimaryGroup: "audit-group"}}
	registerSession(s)
	defer unregisterSession(s.ID)
	s.beginTransfer("download", "/release/file.rar")
	if !DisconnectActiveSession(s.ID) {
		t.Fatal("disconnect failed")
	}
	logins := countSessionsForUser(s.User.Name)
	downloads := countTransfersForUser(s.User.Name, "download")
	t.Logf("after disconnect before handler returns: logins=%d downloads=%d", logins, downloads)
	if logins != 0 || downloads != 0 {
		t.Fatalf("closed session still counted: logins=%d downloads=%d", logins, downloads)
	}
	if countSessionsForGroup("audit-group") != 0 {
		t.Fatal("closed session holds a group login slot")
	}
	if !DisconnectActiveSession(s.ID) {
		t.Fatal("repeated disconnect should be idempotent")
	}
	if snap := listActiveSessions(); len(snap) != 1 || snap[0].LoggedIn {
		t.Fatalf("unexpected closing snapshot: %+v", snap)
	}
}

func TestKickedUserReleasesLoginSlots(t *testing.T) {
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		s := &Session{Conn: a, IsLogged: true, User: &user.User{Name: "audit-kicked"}}
		registerSession(s)
		defer unregisterSession(s.ID)
	}
	if n := kickActiveUser("audit-kicked"); n != 2 {
		t.Fatalf("kicked=%d", n)
	}
	if n := countSessionsForUser("audit-kicked"); n != 0 {
		t.Fatalf("logins=%d", n)
	}
	if n := kickActiveUser("audit-kicked"); n != 0 {
		t.Fatalf("kicked twice: %d", n)
	}
}
