package zipscript

import "testing"

func TestRestrictFilesWithoutForceFirst(t *testing.T) {
	cfg := Config{Enabled: true, SFV: SFVConfig{ForceFirst: false, RestrictFiles: boolPtr(true), PathCheck: []string{"*"}, Users: []string{"*"}}}
	entries := map[string]uint32{"movie.rar": 1}
	err := ValidateUpload(cfg, nil, "/FOREIGN/TV-DE/Release-GRP", "release-subs.rar", []string{"release.sfv"}, nil, entries)
	if err == nil {
		t.Fatal("unlisted archive accepted despite restrict_files")
	}
	if err := ValidateUpload(cfg, nil, "/FOREIGN/TV-DE/Release-GRP", "movie.rar", []string{"release.sfv"}, nil, entries); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUpload(cfg, nil, "/FOREIGN/TV-DE/Release-GRP", "movie.rar", nil, nil, nil); err != nil {
		t.Fatalf("payload before SFV must remain allowed: %v", err)
	}
	cfg.SFV.PathIgnore = []string{"*/Subs"}
	if err := ValidateUpload(cfg, nil, "/FOREIGN/TV-DE/Release-GRP/Subs", "release-subs.rar", []string{"release.sfv"}, nil, entries); err != nil {
		t.Fatalf("ignored path rejected: %v", err)
	}
	cfg.SFV.ForceFirst = true
	if err := ValidateUpload(cfg, nil, "/FOREIGN/TV-DE/Release-GRP", "release-subs.rar", []string{"release.sfv"}, nil, entries); err == nil {
		t.Fatal("control: expected rejection with force_first")
	}
}
