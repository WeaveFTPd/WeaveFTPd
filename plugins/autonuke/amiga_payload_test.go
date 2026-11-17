package autonuke

import (
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"weaveftpd/internal/plugin"
)

func TestAmigaArchivesAreNotHalfEmptyWithDefaultPolicy(t *testing.T) {
	data, err := os.ReadFile("config.yml.dist")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"release.dms", "release.LHA", "release.zip", "release.nfo"} {
		t.Run(name, func(t *testing.T) {
			cfg := loadConfig(raw)
			cfg.StateDir = t.TempDir()
			dir := "/0DAY/1115/Release-bADkARMA"
			bridge := &testBridge{entries: map[string][]plugin.FileEntry{dir: {{Name: name, Size: 100}}}}
			h := &Handler{cfg: cfg, svc: &plugin.Services{Bridge: bridge}}
			rel := releaseCandidate{Path: dir, Name: "Release-bADkARMA", ModTime: time.Now().Add(-90 * time.Minute).Unix()}
			got := h.handleHalfEmpty(rel)
			if want := name == "release.nfo"; got != want {
				t.Fatalf("half-empty=%v, want %v", got, want)
			}
		})
	}
}
