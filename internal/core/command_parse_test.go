package core

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseFTPCommandCWDSpaces(t *testing.T) {
	for _, tc := range []struct {
		line string
		cmd  string
		args []string
	}{
		{"CWD /release/[Techno 2026]", "CWD", []string{"/release/[Techno 2026]"}},
		{"cwd /release/[Techno  2026]", "CWD", []string{"/release/[Techno  2026]"}},
		{"CWD\tSample Folder", "CWD", []string{"Sample Folder"}},
		{"CWD", "CWD", []string{}},
		{"SITE SEARCH something here", "SITE", []string{"SEARCH", "something", "here"}},
		{"PRET RETR file.r00", "PRET", []string{"RETR", "file.r00"}},
		{"AUTH TLS", "AUTH", []string{"TLS"}},
		{" ", "", nil},
	} {
		cmd, args := parseFTPCommand(tc.line)
		if cmd != tc.cmd || !reflect.DeepEqual(args, tc.args) {
			t.Errorf("%q: got %q %#v, want %q %#v", tc.line, cmd, args, tc.cmd, tc.args)
		}
	}
}

func TestParseFTPCommandSTATSpaces(t *testing.T) {
	for _, tc := range []struct {
		line string
		args []string
	}{
		{"STAT", []string{}},
		{"STAT -l", []string{"-l"}},
		{"STAT -l -a", []string{"-l", "-a"}},
		{"STAT /release/[Alternative 2026]", []string{"/release/[Alternative 2026]"}},
		{"STAT -l /release/[Alternative 2026]", []string{"-l", "/release/[Alternative 2026]"}},
		{"stat -al /release/[Alternative  2026]", []string{"-al", "/release/[Alternative  2026]"}},
		{"STAT\t-l\t-a\tSample  Folder", []string{"-l", "-a", "Sample  Folder"}},
		{"STAT -l Sample -a Folder", []string{"-l", "Sample -a Folder"}},
		{"STAT -l ./-Sample Folder", []string{"-l", "./-Sample Folder"}},
		{"STAT -l /release/Café 日本", []string{"-l", "/release/Café 日本"}},
		{"STAT -l /release/Tab\tFolder", []string{"-l", "/release/Tab\tFolder"}},
		{"STAT -l .", []string{"-l", "."}},
	} {
		cmd, args := parseFTPCommand(tc.line)
		if cmd != "STAT" || !reflect.DeepEqual(args, tc.args) {
			t.Errorf("%q: got %q %#v, want STAT %#v", tc.line, cmd, args, tc.args)
		}
	}
}

type cwdPathTestBridge struct {
	MasterBridge
	root string
}

func (b *cwdPathTestBridge) ResolvePath(path string) string { return path }
func (b *cwdPathTestBridge) GetPathEntry(path string) (MasterFileEntry, bool) {
	info, err := os.Stat(filepath.Join(b.root, filepath.FromSlash(strings.TrimPrefix(path, "/"))))
	if err != nil {
		return MasterFileEntry{}, false
	}
	return MasterFileEntry{Name: info.Name(), IsDir: info.IsDir()}, true
}
func (b *cwdPathTestBridge) GetAggregateDiskUsage() (int64, int64, bool) {
	return 1 << 30, 2 << 30, true
}

func TestCWDSpacedDirectory(t *testing.T) {
	for _, name := range []string{"[Techno 2026]", "[Techno  2026]", "Sample Folder"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "release", name), 0755); err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			response := make(chan string, 1)
			go func() {
				reader := bufio.NewReader(client)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || !strings.HasPrefix(line, "250-") {
						response <- line
						return
					}
				}
			}()
			s := &Session{Conn: server, Config: &Config{Mode: "master", StoragePath: root}, CurrentDir: "/release",
				MasterManager: &cwdPathTestBridge{root: root}}
			cmd, args := parseFTPCommand("CWD " + name)
			s.processCommand(cmd, args, nil)
			line := <-response
			if !strings.HasPrefix(line, "250 ") || s.CurrentDir != "/release/"+name {
				t.Fatalf("CWD lost path bytes: reply=%q cwd=%q", line, s.CurrentDir)
			}
		})
	}
}

func (*cwdPathTestBridge) GetDirMediaInfo(string) map[string]string { return nil }
func (*cwdPathTestBridge) GetVFSRaceStats(string) ([]VFSRaceUser, []VFSRaceGroup, int64, int, int) {
	return nil, nil, 0, 0, 0
}
