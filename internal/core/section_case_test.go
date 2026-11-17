package core

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSectionWritePathCase(t *testing.T) {
	c := &Config{StrictSectionCase: true, Sections: []string{"/TV-HDRiP", "/FOREIGN/TV-DE"}}
	for _, p := range []string{"/TV-HDRiP", "/TV-HDRiP/Some_RELEASE/Sample/File.MKV", "/TV-HDRIP-other/X", "/FOREIGN/TV-DE/X", "/OTHER/X", "/"} {
		if err := c.ValidateSectionWritePath(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/TV-HDRIP", "/TV-HDRIP/X/a.rar", "/tv-hdrip/X", "/foreign/TV-DE/X", "/FOREIGN/tv-de/X"} {
		if err := c.ValidateSectionWritePath(p); err == nil {
			t.Errorf("allowed %s", p)
		}
	}
	c.Sections = append(c.Sections, "/TV-HDRIP")
	if err := c.ValidateSectionWritePath("/TV-HDRIP/X"); err != nil {
		t.Fatal("explicit distinct section rejected", err)
	}
	c.StrictSectionCase = false
	if err := c.ValidateSectionWritePath("/tv-hdrip/X"); err != nil {
		t.Fatal(err)
	}
	if err := (*Config)(nil).ValidateSectionWritePath("/anything"); err != nil {
		t.Fatal(err)
	}
}

func TestSectionCaseRejectsFTPWriteCommands(t *testing.T) {
	for _, cmd := range []string{"MKD", "RNTO", "PRET", "STOR"} {
		t.Run(cmd, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			server.SetDeadline(time.Now().Add(3 * time.Second))
			client.SetDeadline(time.Now().Add(3 * time.Second))
			s := &Session{Conn: server, Config: &Config{StrictSectionCase: true, Sections: []string{"/TV-HDRiP"}}, CurrentDir: "/", RenameFrom: "/old", ActiveAddr: "127.0.0.1:1"}
			args := []string{"/TV-HDRIP/Release"}
			if cmd == "PRET" {
				args = []string{"STOR", "/TV-HDRIP/Release/file.rar"}
			}
			done := make(chan struct{})
			go func() { defer close(done); s.processCommand(cmd, args, nil) }()
			line, err := bufio.NewReader(client).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			<-done
			if !strings.HasPrefix(line, "550 section path case mismatch: use /TV-HDRiP") {
				t.Fatalf("reply %q", line)
			}
		})
	}
}
