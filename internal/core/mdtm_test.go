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

type mdtmTestBridge struct {
	MasterBridge
	root string
	fail bool
}

func (b *mdtmTestBridge) ResolvePath(p string) string { return p }
func (b *mdtmTestBridge) GetPathEntry(p string) (MasterFileEntry, bool) {
	info, err := os.Stat(filepath.Join(b.root, filepath.FromSlash(strings.TrimPrefix(p, "/"))))
	if err != nil {
		return MasterFileEntry{}, false
	}
	return MasterFileEntry{Name: info.Name(), Owner: "uploader", ModTime: info.ModTime().Unix()}, true
}
func (b *mdtmTestBridge) ListDir(p string) []MasterFileEntry {
	files, _ := os.ReadDir(filepath.Join(b.root, filepath.FromSlash(strings.TrimPrefix(p, "/"))))
	var entries []MasterFileEntry
	for _, f := range files {
		entries = append(entries, MasterFileEntry{Name: f.Name(), Owner: "uploader"})
	}
	return entries
}
func (b *mdtmTestBridge) SetModTime(p string, stamp time.Time) error {
	if b.fail {
		return fmt.Errorf("owning slave unavailable")
	}
	return os.Chtimes(filepath.Join(b.root, filepath.FromSlash(strings.TrimPrefix(p, "/"))), stamp, stamp)
}

func TestMDTMPreserveUploadTimestamp(t *testing.T) {
	for _, master := range []bool{false, true} {
		t.Run(fmt.Sprintf("master=%v", master), func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "iNFO", "Racetrade"), 0755); err != nil {
				t.Fatal(err)
			}
			s := &Session{CurrentDir: "/iNFO/Racetrade", Config: &Config{StoragePath: root, ACLBasePath: "/"},
				User: &user.User{Name: "uploader"}, ACLEngine: &acl.Engine{RulesByType: map[string][]acl.Rule{
					"upload": {{Type: "upload", Path: "/*", Requirement: &acl.Requirement{Anyone: true}}},
				}}}
			bridge := &mdtmTestBridge{root: root}
			if master {
				s.Config.Mode = "master"
				s.MasterManager = bridge
			}
			for _, name := range []string{"RaceTrade.exe", "Race  Trade æ—¥æœ¬.exe", "20261120230009"} {
				file := filepath.Join(root, "iNFO", "Racetrade", name)
				if err := os.WriteFile(file, []byte("uploaded"), 0644); err != nil {
					t.Fatal(err)
				}
				reply := mdtmWireCommand(t, s, "MDTM 20261120230009 "+name)
				if !strings.HasPrefix(reply, "213 ") {
					t.Fatalf("set: %q", reply)
				}
				info, err := os.Stat(file)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.ModTime().UTC().Format("20060102150405"); got != "20261120230009" {
					t.Fatalf("physical timestamp = %s", got)
				}
				if reply := mdtmWireCommand(t, s, "MDTM "+name); reply != "213 20261120230009\r\n" {
					t.Fatalf("query: %q", reply)
				}
			}
			for _, tc := range []struct{ command, prefix string }{
				{"MDTM", "501 "},
				{"MDTM 20261320230009 RaceTrade.exe", "501 "},
				{"MDTM missing.exe", "550 "},
				{"MDTM 20261120230009 missing.exe", "550 "},
			} {
				if reply := mdtmWireCommand(t, s, tc.command); !strings.HasPrefix(reply, tc.prefix) {
					t.Fatalf("%s: %q", tc.command, reply)
				}
			}
			if master {
				bridge.fail = true
				if reply := mdtmWireCommand(t, s, "MDTM 20250101000000 RaceTrade.exe"); !strings.HasPrefix(reply, "550 ") {
					t.Fatalf("slave failure: %q", reply)
				}
			}
			s.ACLEngine = nil
			if reply := mdtmWireCommand(t, s, "MDTM 20250101000000 RaceTrade.exe"); !strings.HasPrefix(reply, "550 Access Denied") {
				t.Fatalf("ACL: %q", reply)
			}
			if reply := mdtmWireCommand(t, s, "MDTM RaceTrade.exe"); reply != "213 20261120230009\r\n" {
				t.Fatalf("failed set changed time: %q", reply)
			}
		})
	}
}

func mdtmWireCommand(t *testing.T, s *Session, line string) string {
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
