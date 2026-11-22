package user

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMailboxIdentitySurvivesStaleSaveAndRename(t *testing.T) {
	t.Chdir(t.TempDir())
	groups := map[string]int{"NoGroup": 0}
	u := &User{Name: "mailtest", PrimaryGroup: "NoGroup", Groups: groups}
	if err := u.Save(); err != nil {
		t.Fatal(err)
	}
	stale, err := LoadUser(u.Name, groups)
	if err != nil {
		t.Fatal(err)
	}
	const id = "0123456789abcdef0123456789abcdef"
	u.MailboxID = id
	if err := u.Save(); err != nil {
		t.Fatal(err)
	}
	stale.Tagline = "updated"
	if err := stale.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := LoadUser(u.Name, groups)
	if err != nil || got.MailboxID != id {
		t.Fatalf("lost identity: %+v %v", got, err)
	}
	got.Name = "renamedmailtest"
	if err := got.Save(); err != nil {
		t.Fatal(err)
	}
	renamed, err := LoadUser(got.Name, groups)
	if err != nil || renamed.MailboxID != id {
		t.Fatal("rename lost mailbox")
	}
	if err := os.Remove(filepath.Join("etc", "users", u.Name)); err != nil {
		t.Fatal(err)
	}
	replacement := &User{Name: u.Name, PrimaryGroup: "NoGroup", Groups: groups}
	if err := replacement.Save(); err != nil {
		t.Fatal(err)
	}
	got, err = LoadUser(u.Name, groups)
	if err != nil || got.MailboxID != "" {
		t.Fatalf("new account inherited mailbox: %+v %v", got, err)
	}
}
