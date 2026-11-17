package master

import (
	"path/filepath"
	"testing"
)

func TestRaceDBSubtreeMutationsAreLiteral(t *testing.T) {
	for _, operation := range []string{"rename", "delete", "scrub"} {
		t.Run(operation, func(t *testing.T) {
			r, err := NewRaceDB(filepath.Join(t.TempDir(), "race.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			from := "/TV-HDRIP/Release_100%"
			target := "/TV-HDRIP/[NUKED]-Release_100%"
			paths := []string{from, from + "/Proof", from + "/Subs/Nested",
				"/TV-HDRiP/Release_100%/Proof", "/TV-HDRIP/ReleaseX100more/Proof", from + "-other/Proof"}
			for _, p := range paths {
				res, err := r.db.Exec(`INSERT INTO releases(path) VALUES (?)`, p)
				if err != nil {
					t.Fatal(err)
				}
				id, _ := res.LastInsertId()
				_, err = r.db.Exec(`INSERT INTO release_files(release_id, filename, uploader, grp, size_bytes, is_present) VALUES (?, 'proof.jpg', 'original', 'team', 123, 1)`, id)
				if err != nil {
					t.Fatal(err)
				}
			}
			switch operation {
			case "rename":
				err = r.RenamePath(from, target, true)
			case "delete":
				err = r.DeletePath(from, true)
			case "scrub":
				err = r.ScrubReleaseRaceMetadata(from, "changed", "newteam")
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, p := range paths {
				wantOwner, wantCount := "original", 1
				if i < 3 {
					switch operation {
					case "rename":
						p = target + p[len(from):]
					case "delete":
						wantCount = 0
					case "scrub":
						wantOwner = "changed"
					}
				}
				var count int
				if err := r.db.QueryRow(`SELECT count(*) FROM releases WHERE path=?`, p).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != wantCount {
					t.Fatalf("%s count=%d want=%d", p, count, wantCount)
				}
				if count != 0 {
					var owner string
					if err := r.db.QueryRow(`SELECT uploader FROM release_files JOIN releases ON releases.id=release_id WHERE path=?`, p).Scan(&owner); err != nil {
						t.Fatal(err)
					}
					if owner != wantOwner {
						t.Fatalf("%s owner=%s want=%s", p, owner, wantOwner)
					}
				}
			}
		})
	}
}

func TestRaceDBRenameCollisionRollsBack(t *testing.T) {
	r, err := NewRaceDB(filepath.Join(t.TempDir(), "race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, p := range []string{"/A", "/A/Proof", "/B/Proof"} {
		if _, err := r.db.Exec(`INSERT INTO releases(path) VALUES (?)`, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.RenamePath("/A", "/B", true); err == nil {
		t.Fatal("expected real destination collision")
	}
	for _, p := range []string{"/A", "/A/Proof", "/B/Proof"} {
		var n int
		if err := r.db.QueryRow(`SELECT count(*) FROM releases WHERE path=?`, p).Scan(&n); err != nil || n != 1 {
			t.Fatalf("lost %s: count=%d error=%v", p, n, err)
		}
	}
}
