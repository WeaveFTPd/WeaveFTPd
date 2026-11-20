package announce

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"weaveftpd/sitebot/internal/event"
	tmpl "weaveftpd/sitebot/internal/template"
)

func TestNukeThemesReadableAndPreserveDetails(t *testing.T) {
	for _, name := range []string{"pzsng", "drftpd"} {
		t.Run(name, func(t *testing.T) {
			theme, err := tmpl.LoadTheme(filepath.Join("..", "..", "etc", "templates", name+".theme"))
			if err != nil {
				t.Fatal(err)
			}
			p := New()
			p.theme = theme
			for _, tc := range []struct {
				kind  event.EventType
				color string
				want  []string
			}{
				{event.EventNuke, "04", []string{"[TV-DE]", "Example.Release-GRP", "NUKEBOT", "x3", "missing.files", "Alice (123MB), Bob (45MB)"}},
				{event.EventUnnuke, "03", []string{"[TV-DE]", "Example.Release-GRP", "NUKEBOT"}},
				{event.EventAutonukeWarn, "07", []string{"AUTONUKE: INCOMPLETE", "[TV-DE]", "Example.Release-GRP", "Alice", "60 minutes", "240 minutes"}},
				{event.EventAutonukeDelete, "04", []string{"DELETE", "[TV-DE]", "Example.Release-GRP", "missing.files"}},
			} {
				t.Run(string(tc.kind), func(t *testing.T) {
					outs, err := p.OnEvent(&event.Event{Type: tc.kind, Section: "TV-DE", User: "NUKEBOT", Path: "/TV-DE/Example.Release-GRP", Data: map[string]string{
						"relname": "Example.Release-GRP", "multiplier": "3", "reason": "missing.files",
						"nukees": "Alice (123MB), Bob (45MB)", "tag": "ANUKEINC", "owner": "Alice",
						"warn_after": "60 minutes", "nuke_after": "240 minutes",
					}})
					if err != nil || len(outs) == 0 {
						t.Fatalf("outputs=%v err=%v", outs, err)
					}
					var all strings.Builder
					var colored strings.Builder
					for _, out := range outs {
						if strings.TrimSpace(out.Text) == "" {
							continue
						}
						if !strings.HasPrefix(out.Text, "\x02\x03"+tc.color) {
							t.Errorf("missing bold colored label: %q", out.Text)
						}
						if strings.Count(out.Text, "\x02")%2 != 0 {
							t.Errorf("unbalanced bold: %q", out.Text)
						}
						for _, unwanted := range []string{"%relname", "%nukees", "%b"} {
							if strings.Contains(out.Text, unwanted) {
								t.Errorf("unwanted formatting %q in %q", unwanted, out.Text)
							}
						}
						colored.WriteString(out.Text)
						all.WriteString(regexp.MustCompile(`\x03(?:[0-9]{1,2})?|\x02`).ReplaceAllString(out.Text, ""))
					}
					color := "\x03" + p.sectionColor("TV-DE", 2)
					if !strings.Contains(colored.String(), "\x02["+color+"TV-DE\x03]\x02") {
						t.Errorf("section must be bold in its own color: %q", colored.String())
					}
					for _, user := range []string{"NUKEBOT", "Alice"} {
						if strings.Contains(all.String(), user) {
							index := strings.Index(colored.String(), color+user)
							if index < 0 || strings.Count(colored.String()[:index], "\x02")%2 != 0 {
								t.Errorf("user %s must use section color without bold: %q", user, colored.String())
							}
						}
					}
					if !strings.Contains(colored.String(), "\x02\x0314Example.Release-GRP\x03\x02") {
						t.Errorf("release must be bold gray: %q", colored.String())
					}
					for _, want := range tc.want {
						if !strings.Contains(all.String(), want) {
							t.Errorf("missing %q in %q", want, all.String())
						}
					}
				})
			}
		})
	}
}

func TestAutonukeBlocksAllReasons(t *testing.T) {
	for _, name := range []string{"pzsng", "drftpd"} {
		theme, err := tmpl.LoadTheme(filepath.Join("..", "..", "etc", "templates", name+".theme"))
		if err != nil {
			t.Fatal(err)
		}
		p := New()
		p.theme = theme
		for _, reason := range []string{"Empty", "Incomplete", "Half-Empty Release", "Banned", "custom.reason"} {
			outs, err := p.OnEvent(&event.Event{Type: event.EventAutonukeWarn, Section: "MP3", Path: "/MP3/Example.Release-GRP", Data: map[string]string{
				"reason": reason, "owner": "Alice", "warn_after": "60 minutes", "nuke_after": "240 minutes",
			}})
			if err != nil || len(outs) != 1 {
				t.Fatalf("%s %s: %v %v", name, reason, outs, err)
			}
			lines := strings.Split(outs[0].Text, "\n")
			if len(lines) != 5 || lines[4] != "\u00a0" {
				t.Fatalf("expected four lines and separator: %q", outs[0].Text)
			}
			if !strings.Contains(lines[0], "\x0307"+strings.ToUpper(reason)+"\x03") {
				t.Errorf("reason not orange: %q", lines[0])
			}
			for i, label := range []string{"AUTONUKE:", "Owner:", "Warned after", "Nukes after"} {
				if !strings.HasPrefix(lines[i], "\x02\x0307AUTONUKE:\x03\x02") || !strings.Contains(lines[i], label) || strings.Count(lines[i], "\x02")%2 != 0 {
					t.Errorf("bad warning line: %q", lines[i])
				}
			}
		}
		outs, _ := p.OnEvent(&event.Event{Type: event.EventAutonukeDelete, Section: "MP3", Path: "/MP3/Example.Release-GRP", Data: map[string]string{"reason": "deleted after 180 minutes"}})
		lines := strings.Split(outs[0].Text, "\n")
		if len(lines) != 3 || lines[2] != "\u00a0" || !strings.Contains(lines[1], "Deleted release after 180 minutes") {
			t.Errorf("bad delete block: %q", outs[0].Text)
		}
		outs, _ = p.OnEvent(&event.Event{Type: event.EventAutonukeWarn, Section: "MP3", Path: "/MP3/Example.Release-GRP", Data: map[string]string{"reason": "Empty"}})
		if len(strings.Split(outs[0].Text, "\n")) != 2 {
			t.Errorf("empty fields must not add lines: %q", outs[0].Text)
		}
		outs, _ = p.OnEvent(&event.Event{Type: event.EventNuke, Section: "MP3", Path: "/MP3/Example.Release-GRP", Data: map[string]string{"reason": "arbitrary.custom.reason"}})
		if outs[len(outs)-1].Text != "\u00a0" {
			t.Error("nuke without nukees needs separator")
		}
		if !strings.Contains(outs[1].Text, "\x0307arbitrary.custom.reason\x03") {
			t.Errorf("custom nuke reason not orange: %q", outs[1].Text)
		}
	}
}
