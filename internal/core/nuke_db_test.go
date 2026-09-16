package core

import (
	"path/filepath"
	"testing"
)

func TestNukeHistoryMarkDeletedHidesEntryFromList(t *testing.T) {
	db, err := newNukeHistoryDB(filepath.Join(t.TempDir(), "nukes.db"), false)
	if err != nil {
		t.Fatalf("newNukeHistoryDB: %v", err)
	}
	defer db.db.Close()

	deletedPath := "/TV/[NUKED]-Old.Release-GRP"
	keepPath := "/TV/[NUKED]-Keep.Release-GRP"
	unnukedPath := "/TV/[NUKED]-Restored.Release-GRP"

	for _, entry := range []NukeHistoryEntry{
		{
			OriginalPath: "/TV/Old.Release-GRP",
			CurrentPath:  deletedPath,
			ReleaseName:  "Old.Release-GRP",
			Multiplier:   3,
			Reason:       "old cleanup",
			NukedBy:      "siteop",
			NukedAt:      100,
			Status:       "active",
		},
		{
			OriginalPath: "/TV/Keep.Release-GRP",
			CurrentPath:  keepPath,
			ReleaseName:  "Keep.Release-GRP",
			Multiplier:   2,
			Reason:       "still nuked",
			NukedBy:      "siteop",
			NukedAt:      200,
			Status:       "active",
		},
		{
			OriginalPath:  "/TV/Restored.Release-GRP",
			CurrentPath:   unnukedPath,
			ReleaseName:   "Restored.Release-GRP",
			Multiplier:    1,
			Reason:        "restored",
			NukedBy:       "siteop",
			NukedAt:       300,
			Status:        "unnuked",
			RestoredPath:  "/TV/Restored.Release-GRP",
			UnnukedBy:     "otherop",
			UnnukedAt:     400,
			UsersAffected: 1,
		},
	} {
		if err := db.RecordNuke(entry); err != nil {
			t.Fatalf("RecordNuke(%s): %v", entry.CurrentPath, err)
		}
	}

	entry, err := db.MarkDeleted(deletedPath)
	if err != nil {
		t.Fatalf("MarkDeleted: %v", err)
	}
	if entry.Status != "deleted" {
		t.Fatalf("MarkDeleted status = %q, want deleted", entry.Status)
	}
	if active, err := db.FindActiveByPath(deletedPath); err != nil || active != nil {
		t.Fatalf("FindActiveByPath deleted row = %#v, %v; want nil, nil", active, err)
	}

	entries, err := db.List("", 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	assertNukeListHasPath(t, entries, keepPath)
	assertNukeListHasPath(t, entries, unnukedPath)
	assertNukeListMissingPath(t, entries, deletedPath)

	filtered, err := db.List("Old.Release", 100)
	if err != nil {
		t.Fatalf("List filtered: %v", err)
	}
	assertNukeListMissingPath(t, filtered, deletedPath)
}

func assertNukeListHasPath(t *testing.T, entries []NukeHistoryEntry, want string) {
	t.Helper()
	for _, entry := range entries {
		if entry.CurrentPath == want {
			return
		}
	}
	t.Fatalf("nuke history missing %s in %#v", want, entries)
}

func assertNukeListMissingPath(t *testing.T, entries []NukeHistoryEntry, path string) {
	t.Helper()
	for _, entry := range entries {
		if entry.CurrentPath == path {
			t.Fatalf("nuke history still contains %s in %#v", path, entries)
		}
	}
}
