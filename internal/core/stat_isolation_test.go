package core

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"weaveftpd/internal/acl"
	"weaveftpd/internal/user"
)

func TestSTATDoesNotInheritPreparedListing(t *testing.T) {
	for _, prepared := range []string{"LIST", "NLST", "MLSD"} {
		s := &Session{CurrentDir: "/NSW/Dispatch", PretCmd: prepared, PretArg: "/X265/Iron.Maiden"}
		for _, args := range [][]string{{"-l"}, {"-la"}, {"-l", "."}, {"-l", "/NSW/Explicit"}} {
			want := s.CurrentDir
			if len(args) > 1 && args[1] != "." {
				want = args[1]
			}
			if got := s.resolveListTargetPath("STAT", args, nil); got != want {
				t.Errorf("PRET %s %s; STAT %v resolves to %q, want %q", prepared, s.PretArg, args, got, want)
			}
		}
	}
}

type statIsolationBridge struct{ MasterBridge }

func (*statIsolationBridge) ResolvePath(p string) string { return p }
func (*statIsolationBridge) GetAggregateDiskUsage() (int64, int64, bool) {
	return 1 << 30, 2 << 30, true
}
func (*statIsolationBridge) GetPathEntry(p string) (MasterFileEntry, bool) {
	return MasterFileEntry{IsDir: true}, true
}
func (*statIsolationBridge) ListDir(p string) []MasterFileEntry {
	name := "own.r03"
	if p == "/X265/Iron.Maiden" {
		name = "foreign.r03"
	}
	return []MasterFileEntry{{Name: name, Size: 1}}
}

func TestSTATWireListingIsolationAfterCWD(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	s := &Session{Conn: server, CurrentDir: "/X265/Iron.Maiden", PretCmd: "LIST", PretArg: "/X265/Iron.Maiden",
		Config: &Config{Mode: "master", ACLBasePath: "/"}, MasterManager: &statIsolationBridge{}, QuietMode: true,
		User: &user.User{Name: "test"}, ACLEngine: &acl.Engine{RulesByType: map[string][]acl.Rule{
			"list": {{Type: "list", Path: "/*", Requirement: &acl.Requirement{Anyone: true}}},
		}}}
	reader := bufio.NewReader(client)
	command := func(line, final string) string {
		t.Helper()
		done := make(chan string, 1)
		go func() {
			var out strings.Builder
			for {
				line, err := reader.ReadString('\n')
				out.WriteString(line)
				if err != nil || strings.HasPrefix(line, final) {
					done <- out.String()
					return
				}
			}
		}()
		cmd, args := parseFTPCommand(line)
		s.processCommand(cmd, args, nil)
		return <-done
	}
	for _, dir := range []string{"/NSW/Dispatch", "/MP3/Release/[Electronic 2026]", "/MP3/Release/[Electronic  2026]"} {
		if got := command("CWD "+dir, "250 "); s.CurrentDir != dir || !strings.Contains(got, "250 Directory changed") {
			t.Fatalf("CWD changed path: cwd=%q reply=%q", s.CurrentDir, got)
		}
		got := command("STAT -l", "213 ")
		if strings.Contains(got, "foreign.r03") || !strings.Contains(got, "own.r03") {
			t.Fatalf("1-byte entry from PRET directory leaked after CWD %q: %s", dir, got)
		}
	}
}
