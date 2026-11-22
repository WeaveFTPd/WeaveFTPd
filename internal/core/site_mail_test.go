package core

import (
	"os"
	"strings"
	"testing"

	"weaveftpd/internal/user"
)

func TestMailCommandsAndLoginNotice(t *testing.T) {
	t.Chdir(t.TempDir())
	old := privateMail
	privateMail = &mailStore{dir: "userdata/mail"}
	t.Cleanup(func() { privateMail = old; clearPasswdCache() })
	groups := map[string]int{"NoGroup": 0}
	for _, name := range []string{"sender", "receiver", "outsider"} {
		u := &user.User{Name: name, PrimaryGroup: "NoGroup", Groups: groups}
		if err := u.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("etc/passwd", []byte("sender:x:1:0\nreceiver:x:2:0\noutsider:x:3:0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conn := &bufferConn{}
	s := &Session{Conn: conn, IsLogged: true, User: &user.User{Name: "sender"}, GroupMap: groups, Config: &Config{PasswdFile: "etc/passwd"}}
	s.HandleSiteMail("MSG", []string{"receiver", "private-body"})
	if !strings.Contains(conn.String(), "200 Message 1 delivered") {
		t.Fatal(conn.String())
	}
	conn.Reset()
	s.User = &user.User{Name: "receiver"}
	s.emitMailNotice()
	if !strings.Contains(conn.String(), "1 unread") {
		t.Fatal(conn.String())
	}
	conn.Reset()
	s.HandleSiteMail("MAIL", nil)
	if !strings.Contains(conn.String(), "NEW from sender") || strings.Contains(conn.String(), "private-body") {
		t.Fatal(conn.String())
	}
	conn.Reset()
	s.User = &user.User{Name: "outsider"}
	s.HandleSiteMail("READ", []string{"1"})
	if !strings.HasPrefix(conn.String(), "550") {
		t.Fatal(conn.String())
	}
	conn.Reset()
	s.User = &user.User{Name: "receiver"}
	s.HandleSiteMail("READ", []string{"1"})
	if !strings.Contains(conn.String(), "private-body") {
		t.Fatal(conn.String())
	}
	conn.Reset()
	s.emitMailNotice()
	if conn.Len() != 0 {
		t.Fatal("read message still announced", conn.String())
	}
	s.HandleSiteMail("DELMSG", []string{"ALL"})
	conn.Reset()
	s.HandleSiteMail("READ", []string{"1"})
	if !strings.HasPrefix(conn.String(), "550") {
		t.Fatal(conn.String())
	}
	conn.Reset()
	s.IsLogged = false
	s.HandleSiteMail("MAIL", nil)
	if !strings.HasPrefix(conn.String(), "530") {
		t.Fatal(conn.String())
	}
}

func TestMailLogRedaction(t *testing.T) {
	line := sanitizeLoggedFTPLine("SITE MSG receiver private-secret")
	if strings.Contains(line, "private-secret") || !strings.Contains(line, "receiver") {
		t.Fatal(line)
	}
	args := sanitizeSiteArgsForLog("MSG", []string{"receiver", "private-secret"})
	if strings.Contains(strings.Join(args, " "), "private-secret") {
		t.Fatal(args)
	}
}
