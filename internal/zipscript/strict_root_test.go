package zipscript

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStrictRootServerConfig(t *testing.T) {
	name := os.Getenv("WEAVE_STRICT_CONFIG")
	if name == "" {
		t.Skip("server configuration not supplied")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Zipscript Config `yaml:"zipscript"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	cfg := doc.Zipscript
	if !cfg.SFV.StrictReleaseRoot {
		t.Fatal("strict root is disabled")
	}
	for _, dir := range []string{"/TV-1080P/Release-GRP", "/FOREIGN/TV-DE/Release-GRP", "/MP3/1116/Release-GRP", "/FLAC/1116/Release-GRP"} {
		for _, file := range []string{"foreign.rar", "foreign.mkv", "foreign.zip", "foreign.mp3"} {
			if err := ValidateUpload(cfg, nil, dir, file, nil, nil, nil); err == nil {
				t.Errorf("accepted before SFV: %s/%s", dir, file)
			}
			if err := ValidateUpload(cfg, nil, dir, file, []string{"release.sfv"}, nil, map[string]uint32{"real.rar": 1}); err == nil {
				t.Errorf("accepted outside SFV: %s/%s", dir, file)
			}
		}
	}
	for _, tc := range []struct{ dir, file string }{
		{"/TV-1080P/Release-GRP/Sample", "sample.mkv"},
		{"/TV-1080P/Release-GRP/Subs", "subs.rar"},
		{"/TV-1080P/Release-GRP/Subs", "subs.sfv"},
		{"/0DAY/1116/Release-GRP", "payload.dms"},
		{"/0DAY/1116/Release-GRP", "payload.lha"},
		{"/0DAY/1116/Release-GRP", "payload.zip"},
	} {
		if err := ValidateUpload(cfg, nil, tc.dir, tc.file, nil, nil, nil); err != nil {
			t.Errorf("compatibility %s/%s: %v", tc.dir, tc.file, err)
		}
	}
}

func strictRootConfig() Config {
	return Config{
		Enabled:      true,
		Sections:     SectionsConfig{SFV: []string{"/TV/*", "/MP3/*/*", "/0DAY/*/*"}, Zip: []string{"/0DAY/*/*"}},
		SFV:          SFVConfig{StrictReleaseRoot: true, RestrictFiles: boolPtr(true), DenyDoubleSFV: true, PathCheck: []string{"*"}, PathIgnore: []string{"*/Subs"}},
		AllowedFiles: AllowedFilesConfig{AllowedTypes: []string{"nfo", "jpg", "mkv", "mp4", "avi", "zip", "vob", "m2ts", "ts"}},
	}
}

func TestStrictRootRejectsForeignFiles(t *testing.T) {
	for _, name := range []string{"foreign.rar", "foreign.r00", "foreign.zip", "foreign.mkv", "foreign.mp4", "foreign.avi", "foreign.vob", "foreign.m2ts", "foreign.ts", "foreign.flac", "foreign.mp3", "foreign.lha", "foreign.dms", "foreign.7z", "foreign.exe", "foreign", "FOREIGN.MKV"} {
		for _, manifest := range []map[string]uint32{nil, {}, {"movie.rar": 1}} {
			if err := ValidateUpload(strictRootConfig(), nil, "/TV/Release-GRP", name, []string{"release.sfv"}, nil, manifest); err == nil {
				t.Errorf("accepted %s with manifest %v", name, manifest)
			}
		}
		if err := ValidateUpload(strictRootConfig(), nil, "/TV/Release-GRP", name, nil, nil, map[string]uint32{raceEntryKey(name): 1}); err != nil {
			t.Errorf("listed %s rejected: %v", name, err)
		}
	}
}

func TestStrictRootPreservesOtherPolicies(t *testing.T) {
	cfg := strictRootConfig()
	for _, tc := range []struct{ dir, name string }{
		{"/TV/Release-GRP/Sample", "sample.mkv"},
		{"/TV/Release-GRP/sample", "sample.mp4"},
		{"/TV/Release-GRP/Subs", "subs.rar"},
		{"/TV/Release-GRP/Subs", "subs.sfv"},
		{"/TV/Release-GRP", "release.nfo"},
		{"/TV/Release-GRP", "cover.jpg"},
		{"/TV/Release.DIRFIX-GRP", "release.nfo"},
		{"/0DAY/1116/Release-GRP", "payload.zip"},
		{"/0DAY/1116/Release-GRP", "payload.dms"},
		{"/0DAY/1116/Release-GRP", "payload.lha"},
		{"/TV/Release-GRP/CD1", "disc.rar"},
	} {
		if err := ValidateUpload(cfg, nil, tc.dir, tc.name, nil, nil, nil); err != nil {
			t.Errorf("%s/%s: %v", tc.dir, tc.name, err)
		}
	}
	if err := ValidateUpload(cfg, nil, "/MP3/1116/Release-GRP", "track.mp3", nil, nil, nil); err == nil {
		t.Fatal("dated release bypassed SFV-first")
	}
	if err := ValidateUpload(cfg, nil, "/TV/Release-GRP", "other.sfv", []string{"release.sfv"}, nil, map[string]uint32{"movie.rar": 1}); err == nil {
		t.Fatal("second SFV accepted")
	}
	cfg.SFV.StrictReleaseRoot = false
	if err := ValidateUpload(cfg, nil, "/TV/Release-GRP", "movie.mkv", nil, nil, nil); err != nil {
		t.Fatalf("legacy behavior changed: %v", err)
	}
	cfg.SFV.StrictReleaseRoot = true
	cfg.SFV.RestrictFiles = boolPtr(false)
	if err := ValidateUpload(cfg, nil, "/TV/Release-GRP", "movie.mkv", nil, nil, nil); err != nil {
		t.Fatalf("restrict_files override ignored: %v", err)
	}
	cfg.SFV.RestrictFiles = boolPtr(true)
	cfg.SFV.PathIgnore = []string{"/TV/*"}
	if err := ValidateUpload(cfg, nil, "/TV/Release-GRP", "movie.mkv", nil, nil, nil); err != nil {
		t.Fatalf("path exemption ignored: %v", err)
	}
}

func TestStrictRootConfigOptIn(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("sfv:\n  strict_release_root: true\n"), &cfg); err != nil || !cfg.SFV.StrictReleaseRoot {
		t.Fatalf("strict root configuration not loaded: %v", err)
	}
	if (Config{}).SFV.StrictReleaseRoot {
		t.Fatal("existing installations must remain opt-in")
	}
}
