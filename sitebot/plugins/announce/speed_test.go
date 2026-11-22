package announce

import (
	"strings"
	"testing"

	"weaveftpd/sitebot/internal/event"
)

func TestScaleSpeed(t *testing.T) {
	for input, want := range map[string]string{
		"62.12MB/s": "62.12MB/s", "1230.55MB/s": "1.20GB/s",
		"1847.57MB/s": "1.80GB/s", "1024MB/s": "1.00GB/s",
		"1023MB/s": "1023.00MB/s", "0.50MB/s": "512.00KB/s",
		"1024GB/s": "1.00TB/s", "1024TB/s": "1.00PB/s",
		"512B/s": "512.00B/s", "0.00MB/s": "0.00B/s",
		"1230.55": "1230.55", "unknown": "unknown",
	} {
		if got := scaleSpeed(input); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}

func TestAnnounceStatsScaleSpeed(t *testing.T) {
	p := New()
	for _, kind := range []event.EventType{event.EventRaceStats, event.EventRaceUser, event.EventRaceGroup, event.EventRaceEnd} {
		evt := &event.Event{Type: kind, Speed: 1230.55, Data: map[string]string{
			"u_slowest_speed": "62.12MB/s", "u_fastest_speed": "1230.55MB/s",
			"u_racer_speed": "1230.55MB/s", "g_speed": "1847.57MB/s",
			"t_avgspeed": "1847.57MB/s", "leader_speed": "1230.55MB/s",
			"u_race_speed": "1230.55MB/s", "speed_kbps": "1230.55",
		}}
		vars := p.vars(evt)
		for _, key := range []string{"u_speed", "speed", "u_fastest_speed", "u_racer_speed", "leader_speed", "leadspeed", "u_race_speed"} {
			if vars[key] != "1.20GB/s" {
				t.Errorf("%s %s = %q", kind, key, vars[key])
			}
		}
		if vars["g_speed"] != "1.80GB/s" || vars["t_avgspeed"] != "1.80GB/s" || vars["u_slowest_speed"] != "62.12MB/s" || vars["speed_kbps"] != "1230.55" {
			t.Fatalf("incorrect vars: %v", vars)
		}
		outputs, err := p.OnEvent(evt)
		if err != nil {
			t.Fatal(err)
		}
		for _, output := range outputs {
			if strings.Contains(output.Text, "1230.55MB/s") || strings.Contains(output.Text, "1847.57MB/s") {
				t.Errorf("unscaled %s: %s", kind, output.Text)
			}
		}
	}
	outputs, err := p.OnEvent(&event.Event{Type: event.EventRaceFooter})
	if err != nil || len(outputs) != 1 {
		t.Fatalf("stats footer: %+v, %v", outputs, err)
	}
	for _, want := range []string{"62.12MB/s", "1.20GB/s", "1.80GB/s"} {
		if !strings.Contains(outputs[0].Text, want) {
			t.Errorf("stats block missing %s: %s", want, outputs[0].Text)
		}
	}
}
