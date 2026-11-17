package zipscript

import "testing"

func TestAmigaPayloadsInZipSections(t *testing.T) {
	cfg := Config{Enabled: true,
		Sections:     SectionsConfig{Zip: []string{"/0DAY/*/*"}, SFV: []string{"/0DAY/*/*", "/TV/*"}},
		AllowedFiles: AllowedFilesConfig{AllowedTypes: []string{"zip", "nfo"}},
		SFV:          SFVConfig{ForceFirst: true},
	}
	for _, name := range []string{"bk-gzs20.dms", "bk-sb30h.lha", "release.zip", "release.z01", "UPPER.DMS", "UPPER.LHA"} {
		if !IsZipPayloadName(name) {
			t.Errorf("payload rejected: %s", name)
		}
		if err := ValidateUpload(cfg, nil, "/0DAY/1115/Release-GRP", name, []string{"release.nfo"}, nil, nil); err != nil {
			t.Errorf("archive without SFV rejected: %s: %v", name, err)
		}
		if !IsRacePayloadFileForDir(cfg, "/0DAY/1115/Release-GRP", name) {
			t.Errorf("untracked payload: %s", name)
		}
	}
	for _, name := range []string{"file.dms", "file.lha"} {
		if IsAllowedTypeForDir(cfg, "/TV/Release-GRP", name) {
			t.Errorf("widened unrelated section policy: %s", name)
		}
		if IsZipRecoverableArchiveName(name) {
			t.Errorf("native archive passed to ZIP decoder: %s", name)
		}
	}
	for _, name := range []string{"file.nfo", "file.dms.exe", "file.lha.bak"} {
		if IsZipPayloadName(name) {
			t.Errorf("not a payload: %s", name)
		}
	}
	entries := []ZipEntryInfo{{Name: "one.dms", Size: 100}, {Name: "two.lha", Size: 100}, {Name: "three.zip", Size: 100}, {Name: "release.nfo", Size: 100}, {Name: "nested.dms", IsDir: true}}
	if got := ZipDirPayloadCount(entries); got != 3 {
		t.Fatalf("payload count: %d", got)
	}
	if ZipDirComplete(entries, 0) {
		t.Fatal("unknown expected count reported complete")
	}
	if ZipDirComplete(entries, 4) {
		t.Fatal("missing part reported complete")
	}
	if !ZipDirComplete(entries, 3) {
		t.Fatal("known complete archive set not recognized")
	}
}

type archiveIntegrityProbe struct {
	ZipRuntimeBridge
	checks int
}

func (p *archiveIntegrityProbe) CheckZipIntegrity(string) (bool, error) { p.checks++; return true, nil }

func TestNativeAmigaArchivesDoNotUseZipIntegrityChecker(t *testing.T) {
	p := &archiveIntegrityProbe{}
	cfg := Config{Enabled: true, Sections: SectionsConfig{Zip: []string{"/0DAY/*/*"}}}
	for _, name := range []string{"file.dms", "file.lha"} {
		deleted, err := CheckUploadedZipIntegrity(p, cfg, "/0DAY/1115/R", "/0DAY/1115/R/"+name, name)
		if deleted || err != nil || p.checks != 0 {
			t.Fatalf("native archive checked as ZIP: %s", name)
		}
		if err := RefreshZipDIZFromArchive(p, "/0DAY/1115/R", "/0DAY/1115/R/"+name, name); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, err := CheckUploadedZipIntegrity(p, cfg, "/0DAY/1115/R", "/0DAY/1115/R/file.zip", "file.zip"); deleted || err != nil || p.checks != 1 {
		t.Fatalf("ZIP verification changed: deleted=%v err=%v checks=%d", deleted, err, p.checks)
	}
}
