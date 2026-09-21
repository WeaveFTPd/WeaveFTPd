package acl

import (
	"os"
	"path/filepath"
	"testing"

	"weaveftpd/internal/user"
)

func TestLoadStructuredYAMLRules(t *testing.T) {
	data := []byte(`
roles:
  anyone:
    anyone: true
  staff:
    any_groups: ["STAFF", "SiteOP"]
  siteop:
    all_flags: ["1"]
  weaveftpd_bot:
    users: ["weaveftpd"]

rules:
  sitecmd:
    - allow: [HELP, AFFILS, PRE]
      required: $anyone
    - allow: [WHO, SWHO]
      required: $staff
    - allow: [REHASH]
      required: $siteop
    - deny: ["*"]
      required:
        nobody: true
  nuke:
    - path: /site/*
      required: $weaveftpd_bot
`)

	e := &Engine{RulesByType: map[string][]Rule{}}
	if loaded, err := loadYAMLRules(e, data); err != nil || !loaded {
		t.Fatalf("loadYAMLRules() = (%v, %v), want (true, nil)", loaded, err)
	}

	if got := len(e.RulesByType["sitecmd"]); got != 7 {
		t.Fatalf("len(sitecmd rules) = %d, want 7", got)
	}
	if got := len(e.RulesByType["nuke"]); got != 1 {
		t.Fatalf("len(nuke rules) = %d, want 1", got)
	}

	anyUser := &user.User{Name: "tester"}
	staffUser := &user.User{Name: "staffer", PrimaryGroup: "STAFF", Groups: map[string]int{"STAFF": 0}}
	siteopUser := &user.User{Name: "siteop", Flags: "1"}
	weaveftpdBot := &user.User{Name: "weaveftpd"}

	if !e.CanPerformRuleOnly(anyUser, "sitecmd", "AFFILS") {
		t.Fatal("public AFFILS rule should allow any user")
	}
	if e.CanPerformRuleOnly(anyUser, "sitecmd", "WHO") {
		t.Fatal("WHO should not be public")
	}
	if !e.CanPerformRuleOnly(staffUser, "sitecmd", "WHO") {
		t.Fatal("WHO should allow staff user")
	}
	if !e.CanPerformRuleOnly(siteopUser, "sitecmd", "REHASH") {
		t.Fatal("REHASH should allow siteop user")
	}
	if !e.CanPerform(weaveftpdBot, "NUKE", "/site/MP3/Release-GRP") {
		t.Fatal("weaveftpd bot should be allowed to nuke in structured config")
	}
}

func TestDefaultPermissionsExposeNukesButGateNukeCommands(t *testing.T) {
	e, err := LoadEngine(filepath.Join("..", "..", "etc", "permissions.yml"))
	if err != nil {
		t.Fatalf("LoadEngine(default permissions) failed: %v", err)
	}

	normal := &user.User{Name: "normal"}
	nuker := &user.User{
		Name:         "nuker",
		PrimaryGroup: "NUKERS",
		Groups:       map[string]int{"NUKERS": 0},
	}
	legacyNuker := &user.User{Name: "legacy-nuker", Flags: "1A"}
	legacyUnnuker := &user.User{Name: "legacy-unnuker", Flags: "1B"}
	bot := &user.User{Name: "weaveftpd"}

	if !e.CanPerformRuleOnly(normal, "sitecmd", "NUKES") {
		t.Fatal("SITE NUKES should be visible to normal users")
	}
	if e.CanPerformRuleOnly(normal, "sitecmd", "NUKE") {
		t.Fatal("SITE NUKE should not be visible to normal users")
	}
	if e.CanPerformRuleOnly(normal, "sitecmd", "UNNUKE") {
		t.Fatal("SITE UNNUKE should not be visible to normal users")
	}
	if !e.CanPerformRuleOnly(nuker, "sitecmd", "NUKE") {
		t.Fatal("SITE NUKE should be visible to nukers")
	}
	if !e.CanPerformRuleOnly(nuker, "sitecmd", "UNNUKE") {
		t.Fatal("SITE UNNUKE should be visible to unnukers")
	}
	if !e.CanPerformRuleOnly(legacyNuker, "sitecmd", "NUKE") {
		t.Fatal("SITE NUKE should be visible to legacy nuker flags")
	}
	if !e.CanPerformRuleOnly(legacyUnnuker, "sitecmd", "UNNUKE") {
		t.Fatal("SITE UNNUKE should be visible to legacy unnuker flags")
	}
	if !e.CanPerformRuleOnly(bot, "sitecmd", "NUKE") {
		t.Fatal("SITE NUKE should be visible to the weaveftpd bot account")
	}
}

func TestStructuredRequirementSupportsAllGroupsAndAnyFlags(t *testing.T) {
	req := &Requirement{
		AllGroups: []string{"Admin", "NUKERS"},
		AnyFlags:  []string{"A", "B"},
	}

	allowed := &user.User{
		Name:         "allowed",
		Flags:        "B",
		PrimaryGroup: "Admin",
		Groups:       map[string]int{"Admin": 0, "NUKERS": 0},
	}
	deniedMissingGroup := &user.User{
		Name:         "denied-group",
		Flags:        "A",
		PrimaryGroup: "Admin",
		Groups:       map[string]int{"Admin": 0},
	}
	deniedMissingFlag := &user.User{
		Name:         "denied-flag",
		Flags:        "1",
		PrimaryGroup: "Admin",
		Groups:       map[string]int{"Admin": 0, "NUKERS": 0},
	}

	if !checkRequirement(req, allowed) {
		t.Fatal("checkRequirement() should allow user matching all groups and any flag")
	}
	if checkRequirement(req, deniedMissingGroup) {
		t.Fatal("checkRequirement() should reject user missing one required group")
	}
	if checkRequirement(req, deniedMissingFlag) {
		t.Fatal("checkRequirement() should reject user missing any required flag")
	}
}

func TestStructuredRequirementSupportsAnyOfAcrossFlagsAndGroups(t *testing.T) {
	req := &Requirement{
		AnyOf: []*Requirement{
			{AllFlags: []string{"1"}},
			{AllGroups: []string{"NUKERS"}},
		},
	}

	flagUser := &user.User{Name: "flag-user", Flags: "1"}
	groupUser := &user.User{
		Name:         "group-user",
		PrimaryGroup: "NUKERS",
		Groups:       map[string]int{"NUKERS": 0},
	}
	denied := &user.User{Name: "denied", Flags: "3"}

	if !checkRequirement(req, flagUser) {
		t.Fatal("any_of should allow user with matching flag branch")
	}
	if !checkRequirement(req, groupUser) {
		t.Fatal("any_of should allow user with matching group branch")
	}
	if checkRequirement(req, denied) {
		t.Fatal("any_of should reject user matching no branch")
	}
}

func TestLoadStructuredYAMLRulesWithAnyOf(t *testing.T) {
	data := []byte(`
roles:
  anyone:
    anyone: true

rules:
  nuke:
    - path: /site/*
      required:
        any_of:
          - all_flags: ["1"]
          - all_groups: ["NUKERS"]
`)

	e := &Engine{RulesByType: map[string][]Rule{}}
	if loaded, err := loadYAMLRules(e, data); err != nil || !loaded {
		t.Fatalf("loadYAMLRules() = (%v, %v), want (true, nil)", loaded, err)
	}

	flagUser := &user.User{Name: "flag-user", Flags: "1"}
	groupUser := &user.User{
		Name:         "group-user",
		PrimaryGroup: "NUKERS",
		Groups:       map[string]int{"NUKERS": 0},
	}
	denied := &user.User{Name: "denied", Flags: "3"}

	if !e.CanPerform(flagUser, "NUKE", "/site/MP3/Release-GRP") {
		t.Fatal("structured any_of should allow matching flag branch")
	}
	if !e.CanPerform(groupUser, "NUKE", "/site/MP3/Release-GRP") {
		t.Fatal("structured any_of should allow matching group branch")
	}
	if e.CanPerform(denied, "NUKE", "/site/MP3/Release-GRP") {
		t.Fatal("structured any_of should reject unmatched user")
	}
}

func TestMatchesRulePathCoversPrivatePathDescendants(t *testing.T) {
	e := &Engine{RulesByType: map[string][]Rule{
		"privpath": {
			{Type: "privpath", Path: "/site/PRE/GROUP", Required: "=GROUP =SiteOP"},
			{Type: "privpath", Path: "/site/LINKS/*", Required: "1"},
		},
	}}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "exact", path: "/site/PRE/GROUP", want: true},
		{name: "child release", path: "/site/PRE/GROUP/Release-GRP", want: true},
		{name: "nested file", path: "/site/PRE/GROUP/Release-GRP/file.rar", want: true},
		{name: "sibling group", path: "/site/PRE/OTHER/Release-GRP", want: false},
		{name: "wildcard", path: "/site/LINKS/something", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.MatchesRulePath("privpath", tt.path)
			if got != tt.want {
				t.Fatalf("MatchesRulePath(privpath, %q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCanPerformCoversExactPathDescendants(t *testing.T) {
	e := &Engine{RulesByType: map[string][]Rule{
		"dirlog": {
			{Type: "dirlog", Path: "/site/MP3", Required: "*"},
			{Type: "dirlog", Path: "/site/PRE/GROUP", Required: "=GROUP =SiteOP"},
		},
	}}

	u := &user.User{
		Name:         "tester",
		PrimaryGroup: "GROUP",
		Groups:       map[string]int{"GROUP": 0},
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "exact root", path: "/site/MP3", want: true},
		{name: "dated dir", path: "/site/MP3/0424", want: true},
		{name: "release below exact rule", path: "/site/MP3/0424/Artist-Album-2026-GRP", want: true},
		{name: "private exact path descendant", path: "/site/PRE/GROUP/Release-GRP", want: true},
		{name: "private nested descendant", path: "/site/PRE/GROUP/Release-GRP/file.rar", want: true},
		{name: "outside subtree", path: "/site/FLAC/0424/Artist-Album-2026-GRP", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.CanPerform(u, "DIRLOG", tt.path)
			if got != tt.want {
				t.Fatalf("CanPerform(DIRLOG, %q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCanPerformSupportsBracePathPatterns(t *testing.T) {
	e := &Engine{RulesByType: map[string][]Rule{
		"dirlog": {
			{Type: "dirlog", Path: "/SERIES-SD/*/{Sample,Subs,Proof}", Required: "$nobody"},
			{Type: "dirlog", Path: "/*", Required: "*"},
		},
		"list": {
			{Type: "list", Path: "/*", Required: "*"},
		},
	}}

	u := &user.User{Name: "tester"}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "sample hidden", path: "/SERIES-SD/Release-GRP/Sample", want: false},
		{name: "subs hidden", path: "/SERIES-SD/Release-GRP/Subs", want: false},
		{name: "proof hidden", path: "/SERIES-SD/Release-GRP/Proof", want: false},
		{name: "release still visible", path: "/SERIES-SD/Release-GRP", want: true},
		{name: "other section visible", path: "/MOVIES-SD/Release-GRP/Sample", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.CanPerform(u, "DIRLOG", tt.path)
			if got != tt.want {
				t.Fatalf("CanPerform(DIRLOG, %q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestPrivpathOverridesBroadListAllow(t *testing.T) {
	e := &Engine{RulesByType: map[string][]Rule{
		"list": {
			{Type: "list", Path: "/*", Requirement: &Requirement{Anyone: true}},
		},
		"privpath": {
			{
				Type: "privpath",
				Path: "/PRIVATE",
				Requirement: &Requirement{
					AllFlags:  []string{"1"},
					AllGroups: []string{"BFF"},
				},
			},
		},
	}}

	denied := &user.User{
		Name:         "regular",
		Flags:        "3",
		PrimaryGroup: "USERS",
		Groups:       map[string]int{"USERS": 0},
	}
	allowed := &user.User{
		Name:         "staff",
		Flags:        "13",
		PrimaryGroup: "BFF",
		Groups:       map[string]int{"BFF": 0},
	}

	if e.CanPerform(denied, "LIST", "/PRIVATE") {
		t.Fatal("privpath should hide /PRIVATE even when a broad LIST allow exists")
	}
	if !e.CanPerform(allowed, "LIST", "/PRIVATE") {
		t.Fatal("privpath should allow user matching all_flags and all_groups")
	}
	if e.CanPerform(denied, "LIST", "/PRIVATE/Release-GRP") {
		t.Fatal("privpath should also hide descendants of /PRIVATE")
	}
}

func TestPrivpathSupportsBuiltInNobodyRoleRef(t *testing.T) {
	data := []byte(`
rules:
  list:
    - allow: ["/*"]
      required: $anyone
  privpath:
    - path: /PRIVATE
      required: $nobody
`)

	e := &Engine{RulesByType: map[string][]Rule{}}
	if loaded, err := loadYAMLRules(e, data); err != nil || !loaded {
		t.Fatalf("loadYAMLRules() = (%v, %v), want (true, nil)", loaded, err)
	}

	u := &user.User{
		Name:         "regular",
		Flags:        "3",
		PrimaryGroup: "USERS",
		Groups:       map[string]int{"USERS": 0},
	}

	if e.CanPerform(u, "LIST", "/PRIVATE") {
		t.Fatal("privpath with $nobody should hide /PRIVATE from every user")
	}
	if e.CanPerform(u, "LIST", "/PRIVATE/Release-GRP") {
		t.Fatal("privpath with $nobody should also hide descendants")
	}
}

func TestLoadEngineRejectsInvalidYAMLPermissionsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "permissions.yml")
	data := []byte("roles:\n\tanyone:\n\t  anyone: true\n\nrules:\n\tsitecmd:\n\t  - allow: [HELP]\n\t    required: $anyone\n")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadEngine(path)
	if err == nil {
		t.Fatal("LoadEngine() error = nil, want invalid YAML error")
	}
}
