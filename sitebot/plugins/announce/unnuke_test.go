package announce

import (
	"path/filepath"
	"strings"
	"testing"
	"weaveftpd/sitebot/internal/event"
	tmpl "weaveftpd/sitebot/internal/template"
)

func TestUnnukeReason(t *testing.T) {
	for _, name := range []string{"pzsng", "drftpd", "fallback"} {
		p := New()
		if name != "fallback" {
			theme, err := tmpl.LoadTheme(filepath.Join("..", "..", "etc", "templates", name+".theme"))
			if err != nil {
				t.Fatal(err)
			}
			p.theme = theme
		}
		for _, reason := range []string{"", "  ", "valid.release proof confirmed"} {
			outs, err := p.OnEvent(&event.Event{Type: event.EventUnnuke, Section: "MP3", Path: "/ARCHiVE/MP3/Release-GRP", User: "NUKEBOT", Data: map[string]string{"reason": reason}})
			want := 2
			if strings.TrimSpace(reason) != "" {
				want = 3
			}
			if err != nil || len(outs) != want {
				t.Fatalf("%s: %v %v", name, outs, err)
			}
			if want == 3 {
				if !strings.Contains(outs[1].Text, reason) {
					t.Fatal("reason lost", outs)
				}
				if name != "fallback" && !strings.Contains(outs[1].Text, "\x0307"+reason) {
					t.Fatal("reason not orange", outs)
				}
			}
			if strings.TrimSpace(outs[len(outs)-1].Text) != "" {
				t.Fatal("missing separator")
			}
		}
	}
}
