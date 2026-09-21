package admincommander

import "testing"

func TestDefaultAllowedCommandsIncludesNukes(t *testing.T) {
	p := New()

	if !p.allowedCommand("NUKES") {
		t.Fatal("default admin commander allowlist should permit SITE NUKES")
	}
	if !p.allowedCommand("nukes") {
		t.Fatal("admin commander allowlist should be case-insensitive")
	}
	if p.allowedCommand("NOPE") {
		t.Fatal("unknown SITE command should remain blocked by default")
	}
}
