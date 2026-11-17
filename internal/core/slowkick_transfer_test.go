package core

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"weaveftpd/internal/plugin"
	"weaveftpd/internal/user"
	"weaveftpd/internal/zipscript"
)

func TestSlowkickReleaseRoot(t *testing.T) {
	cfg := zipscript.Config{Enabled: true, Sections: zipscript.SectionsConfig{ReleaseCheck: []string{"/TV/*", "/0DAY/*/*", "/FOREIGN/TV-DE/*"}}}
	for input, want := range map[string]string{
		"/TV/R/file.rar": "/TV/R", "/TV/R/CD1/Subs/f.rar": "/TV/R",
		"/0DAY/1114/R/f.zip": "/0DAY/1114/R", "/0DAY/1114/f.zip": "",
		"/FOREIGN/TV-DE/R/Subs/f.rar": "/FOREIGN/TV-DE/R", "/UNKNOWN/R/f.rar": "",
	} {
		if got := SlowkickReleaseRoot(cfg, input); got != want {
			t.Fatalf("%s: got %s want %s", input, got, want)
		}
	}
	if got := SlowkickReleaseRoot(zipscript.Config{Enabled: true}, "/TV/R/f.rar"); got != "" {
		t.Fatal(got)
	}
}

func TestAbortActiveSessionTransferPreservesControlAndRejectsStaleSnapshot(t *testing.T) {
	control, peer := net.Pipe()
	defer control.Close()
	defer peer.Close()
	data, dataPeer := net.Pipe()
	defer data.Close()
	defer dataPeer.Close()
	s := &Session{Conn: control}
	registerSession(s)
	defer unregisterSession(s.ID)
	s.beginTransfer("upload", "/TV/R/f.rar")
	defer s.endTransfer()
	s.attachTransferConn(data)
	snap := plugin.ActiveSession{ID: s.ID, TransferDirection: s.TransferDirection, TransferPath: s.TransferPath, TransferStartedAt: s.TransferStartedAt}
	stale := snap
	stale.TransferStartedAt = stale.TransferStartedAt.Add(-time.Second)
	if AbortActiveSessionTransfer(stale, "test") {
		t.Fatal("stale transfer aborted")
	}
	if !AbortActiveSessionTransfer(snap, "test") {
		t.Fatal("not aborted")
	}
	dataPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := dataPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("data connection still open")
	}
	done := make(chan error, 1)
	go func() { _, err := control.Write([]byte("x")); done <- err }()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != nil {
		t.Fatal("control closed:", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type denyUploadPlugin struct{ target string }

func (p *denyUploadPlugin) Name() string                                        { return "upload-test" }
func (p *denyUploadPlugin) Init(*plugin.Services, map[string]interface{}) error { return nil }
func (p *denyUploadPlugin) OnEvent(*plugin.Event) error                         { return nil }
func (p *denyUploadPlugin) Stop() error                                         { return nil }
func (p *denyUploadPlugin) ValidateUpload(u *user.User, target string) error {
	p.target = target
	return fmt.Errorf("release blocked")
}

func TestUploadBanCheckedBeforePRETAndSTOR(t *testing.T) {
	for _, command := range []string{"PRET", "STOR"} {
		t.Run(command, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			p := &denyUploadPlugin{}
			pm := NewPluginManager(false)
			pm.RegisterPlugin(p)
			s := &Session{Conn: server, Config: &Config{PluginManager: pm}, User: &user.User{Name: "tester"}, IsLogged: true, CurrentDir: "/TV/R", ActiveAddr: "127.0.0.1:12345"}
			args := []string{"Subs/f.rar"}
			if command == "PRET" {
				args = []string{"STOR", "Subs/f.rar"}
			}
			done := make(chan bool, 1)
			go func() { done <- s.processCommand(command, args, nil) }()
			client.SetReadDeadline(time.Now().Add(time.Second))
			line, err := bufio.NewReader(client).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(line, "550 upload-test: release blocked") {
				t.Fatal(line)
			}
			if <-done {
				t.Fatal("session closed")
			}
			if p.target != "/TV/R/Subs/f.rar" {
				t.Fatal(p.target)
			}
		})
	}
}
