package bot

import (
	"testing"
	"weaveftpd/sitebot/internal/event"
)

func TestNukeArchiveCategoryPreservesRouting(t *testing.T) {
	b := &Bot{Config: &Config{Sections: []SectionRoute{{Name: "ARCHIVE", Paths: []string{"/ARCHiVE/*"}, Channels: []string{"#archive"}}}}}
	for _, kind := range []event.EventType{event.EventNuke, event.EventUnnuke} {
		e := &event.Event{Type: kind, Section: "MP3", Path: "/ARCHiVE/MP3/1120/Release-GRP"}
		if got := b.resolveEventSection(e); got != "MP3" {
			t.Fatalf("%s section=%s", kind, got)
		}
		if got := b.routeChannels(e, string(kind)); len(got) != 1 || got[0] != "#archive" {
			t.Fatalf("routing changed: %v", got)
		}
	}
	e := &event.Event{Type: event.EventCustom, Section: "MP3", Path: "/ARCHiVE/MP3/1120/Release-GRP"}
	if got := b.resolveEventSection(e); got != "ARCHIVE" {
		t.Fatalf("custom event changed: %s", got)
	}
	b.Config.Sections = append(b.Config.Sections, SectionRoute{Name: "MUSIC", Paths: []string{"/ARCHiVE/MP3/*"}})
	e.Type = event.EventUnnuke
	if got := b.resolveEventSection(e); got != "MUSIC" {
		t.Fatalf("explicit category override lost: %s", got)
	}
}
