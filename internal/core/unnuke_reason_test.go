package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"weaveftpd/internal/acl"
	"weaveftpd/internal/user"
)

type unnukeCapture struct{ events []Event }

func (c *unnukeCapture) Publish(e Event) error { c.events = append(c.events, e); return nil }
func (c *unnukeCapture) Close() error          { return nil }

func TestUnnukeReasonLocalEvent(t *testing.T) {
	// Keep this test independent of the process-wide nuke database and real credits.
	oldInst, oldErr := nukeDBInst, nukeDBErr
	nukeDBInit.Do(func() {})
	nukeDBInst = nil
	nukeDBErr = errors.New("test: no history")
	t.Cleanup(func() {
		nukeDBInst = oldInst
		nukeDBErr = oldErr
		if oldInst == nil && oldErr == nil {
			nukeDBInit = sync.Once{}
		}
	})
	root := t.TempDir()
	permissions := filepath.Join(root, "permissions.yml")
	if err := os.WriteFile(permissions, []byte("roles:\n  anyone: {}\nrules:\n  unnuke:\n    - path: /*\n      required: $anyone\n"), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := acl.LoadEngine(permissions)
	if err != nil {
		t.Fatal(err)
	}
	for i, reason := range []string{"", "valid release proof confirmed"} {
		name := "ReleaseA"
		if i == 1 {
			name = "ReleaseB"
		}
		if err := os.Mkdir(filepath.Join(root, "[NUKED]-"+name), 0700); err != nil {
			t.Fatal(err)
		}
		sink := &unnukeCapture{}
		d := NewEventDispatcher(false)
		d.AddSink(sink)
		conn := &bufferConn{}
		s := &Session{Conn: conn, User: &user.User{Name: "NUKEBOT"}, ACLEngine: engine, CurrentDir: "/", Config: &Config{StoragePath: root, ACLBasePath: "/", EventDispatcher: d}}
		args := append([]string{"/[NUKED]-" + name}, strings.Fields(reason)...)
		s.HandleSiteUnnuke(args)
		if !strings.HasPrefix(conn.String(), "200") {
			t.Fatal(conn.String())
		}
		if len(sink.events) != 1 || sink.events[0].Data["reason"] != reason {
			t.Fatalf("reason lost: %+v", sink.events)
		}
	}
}
