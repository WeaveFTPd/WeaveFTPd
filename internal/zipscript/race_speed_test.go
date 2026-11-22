package zipscript

import (
	"bytes"
	"strings"
	"testing"
)

func TestRaceSpeedUnits(t *testing.T) {
	for _, tc := range []struct {
		speed float64
		want  string
	}{
		{0, "-"}, {-1, "-"}, {512, "512.00B/s"},
		{1024, "1.00KB/s"}, {1024 * 1024, "1.00MB/s"},
		{1230.55 * 1024 * 1024, "1.20GB/s"},
		{1847.57 * 1024 * 1024, "1.80GB/s"},
		{1024 * 1024 * 1024 * 1024, "1.00TB/s"},
	} {
		if got := speed(tc.speed); got != tc.want {
			t.Errorf("speed(%v) = %q; want %q", tc.speed, got, tc.want)
		}
	}
}

func TestRaceStatsRenderScaledSpeeds(t *testing.T) {
	users := []RaceUserStat{{Name: "flatter", Group: "iND", Files: 4, Speed: 1230.55 * 1024 * 1024}}
	groups := []RaceGroupStat{{Name: "iND", Files: 31, Speed: 1847.57 * 1024 * 1024}}
	var full bytes.Buffer
	RenderRaceStats(&full, users, groups, 1<<30, 31, 31, "test")
	if strings.Count(full.String(), "1.20GB/s") != 2 || !strings.Contains(full.String(), "1.80GB/s") {
		t.Fatalf("user/group/total speeds not scaled: %q", full.String())
	}
	var compact bytes.Buffer
	RenderCompactRaceStats(&compact, users, groups, 1<<30, 31, 31)
	if !strings.Contains(compact.String(), "1.20GB/s") {
		t.Fatalf("compact stats not scaled: %q", compact.String())
	}
}
