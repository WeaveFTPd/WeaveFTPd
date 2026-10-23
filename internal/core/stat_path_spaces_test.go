package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaveftpd/internal/acl"
	"weaveftpd/internal/user"
)

type statSpaceTestBridge struct {
	cwdPathTestBridge
	listed []string
}

func (b *statSpaceTestBridge) ListDir(p string) []MasterFileEntry {
	b.listed = append(b.listed, p)
	files, _ := os.ReadDir(filepath.Join(b.root, filepath.FromSlash(strings.TrimPrefix(p, "/"))))
	var entries []MasterFileEntry
	for _, file := range files {
		info, _ := file.Info()
		entries = append(entries, MasterFileEntry{Name: file.Name(), Size: info.Size(), IsDir: file.IsDir()})
	}
	return entries
}

// Send the command and consume its complete reply over a control connection.
func statSpaceWireCommand(t *testing.T, s *Session, line string) string {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	s.Conn = server
	done := make(chan error, 1)
	go func() {
		input, err := bufio.NewReader(server).ReadString('\n')
		if err == nil {
			cmd, args := parseFTPCommand(input)
			s.processCommand(cmd, args, nil)
		}
		done <- err
	}()
	if _, err := fmt.Fprintf(client, "%s\r\n", line); err != nil {
		t.Fatal(err)
	}
	var reply strings.Builder
	reader := bufio.NewReader(client)
	for {
		part, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("control reply for %q: %v (received %q)", line, err, reply.String())
		}
		reply.WriteString(part)
		if len(part) > 3 && part[0] >= '1' && part[0] <= '5' && part[3] == ' ' {
			break
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return reply.String()
}

func TestSTATExplicitSpacedPathsControlReply(t *testing.T) {
	root := t.TempDir()
	for dir, name := range map[string]string{
		"release/[Alternative 2026]":  "correct.r00",
		"release/[Alternative  2026]": "correct.r00",
		"release/Sample -a Folder":    "correct.r00",
		"release/-Sample Folder":      "correct.r00",
		"release/Café 日本":             "correct.r00",
		"release/[Alternative":        "truncated.r00",
		"release":                     "current.r00",
		"foreign":                     "foreign.r00",
	} {
		full := filepath.Join(root, filepath.FromSlash(dir))
		if err := os.MkdirAll(full, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, master := range []bool{false, true} {
		for _, tc := range []struct{ line, target string }{
			{"STAT /release/[Alternative 2026]", "/release/[Alternative 2026]"},
			{"STAT -l /release/[Alternative 2026]", "/release/[Alternative 2026]"},
			{"STAT -al /release/[Alternative  2026]", "/release/[Alternative  2026]"},
			{"STAT -l -a [Alternative 2026]", "/release/[Alternative 2026]"},
			{"STAT\t-l\t[Alternative  2026]", "/release/[Alternative  2026]"},
			{"STAT -l Sample -a Folder", "/release/Sample -a Folder"},
			{"STAT -l ./-Sample Folder", "/release/-Sample Folder"},
			{"STAT -l /release/Café 日本", "/release/Café 日本"},
		} {
			t.Run(fmt.Sprintf("master=%v/%s", master, tc.line), func(t *testing.T) {
				bridge := &statSpaceTestBridge{cwdPathTestBridge: cwdPathTestBridge{root: root}}
				s := &Session{CurrentDir: "/release", PretCmd: "LIST", PretArg: "/foreign",
					Config: &Config{StoragePath: root, ACLBasePath: "/"}, User: &user.User{Name: "test"},
					ACLEngine: &acl.Engine{RulesByType: map[string][]acl.Rule{
						"list": {{Type: "list", Path: "/*", Requirement: &acl.Requirement{Anyone: true}}},
					}}}
				if master {
					s.Config.Mode = "master"
					s.MasterManager = bridge
				}
				reply := statSpaceWireCommand(t, s, tc.line)
				if !strings.HasPrefix(reply, "213-STAT\r\n") || !strings.HasSuffix(reply, "213 End of status.\r\n") || !strings.Contains(reply, "correct.r00") {
					t.Fatalf("expected complete listing for %q, got %q", tc.target, reply)
				}
				for _, wrong := range []string{"truncated.r00", "foreign.r00", "current.r00"} {
					if strings.Contains(reply, wrong) {
						t.Fatalf("wrong directory's %s appeared in %q", wrong, reply)
					}
				}
				if master && (len(bridge.listed) != 1 || bridge.listed[0] != tc.target) {
					t.Fatalf("bridge listed %v, want only %q", bridge.listed, tc.target)
				}
				if s.CurrentDir != "/release" || s.PretCmd != "LIST" || s.PretArg != "/foreign" {
					t.Fatal("STAT changed CWD or prepared transfer state")
				}
			})
		}
	}
}

func TestSTATSpacedPathHonorsPrivpath(t *testing.T) {
	for _, master := range []bool{false, true} {
		t.Run(fmt.Sprintf("master=%v", master), func(t *testing.T) {
			bridge := &statSpaceTestBridge{}
			s := &Session{CurrentDir: "/", PretCmd: "LIST", PretArg: "/public",
				Config: &Config{ACLBasePath: "/"}, User: &user.User{Name: "regular", Flags: "3"},
				ACLEngine: &acl.Engine{RulesByType: map[string][]acl.Rule{
					"list":     {{Type: "list", Path: "/*", Requirement: &acl.Requirement{Anyone: true}}},
					"privpath": {{Type: "privpath", Path: "/Private Folder", Requirement: &acl.Requirement{Nobody: true}}},
				}}}
			if master {
				s.Config.Mode = "master"
				s.MasterManager = bridge
			}
			reply := statSpaceWireCommand(t, s, "STAT -l /Private Folder")
			if reply != "550 /Private Folder: no such file or directory\r\n" || len(bridge.listed) != 0 {
				t.Fatalf("private spaced path was not rejected before listing: %q, calls=%v", reply, bridge.listed)
			}
		})
	}
}
