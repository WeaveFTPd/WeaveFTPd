package core

import (
	"database/sql"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const nukeDBPath = "userdata/nukes.db"

type NukeHistoryEntry struct {
	ID                   int64
	OriginalPath         string
	CurrentPath          string
	ReleaseName          string
	Multiplier           int
	Reason               string
	NukedBy              string
	NukedAt              int64
	UsersAffected        int
	TotalBytes           int64
	TotalCreditsRemoved  int64
	Nukees               string
	NukeesData           string // JSON map user->{bytes,credits} removed, for exact unnuke
	Status               string
	UnnukedBy            string
	UnnukedAt            int64
	RestoredPath         string
	TotalCreditsRestored int64
}

type NukeHistoryDB struct {
	db    *sql.DB
	mu    sync.RWMutex
	debug bool
}

var (
	nukeDBInit sync.Once
	nukeDBInst *NukeHistoryDB
	nukeDBErr  error
)

func GetNukeHistoryDB(debug bool) (*NukeHistoryDB, error) {
	nukeDBInit.Do(func() {
		nukeDBInst, nukeDBErr = newNukeHistoryDB(nukeDBPath, debug)
	})
	if nukeDBInst != nil {
		nukeDBInst.debug = debug
	}
	return nukeDBInst, nukeDBErr
}

func newNukeHistoryDB(dbPath string, debug bool) (*NukeHistoryDB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create nuke db dir: %w", err)
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open nuke db: %w", err)
	}
	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, stmt := range pragmas {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("init pragma %q: %w", stmt, err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS nukes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    current_path TEXT NOT NULL,
    release_name TEXT NOT NULL DEFAULT '',
    multiplier INTEGER NOT NULL DEFAULT 1,
    reason TEXT NOT NULL DEFAULT '',
    nuked_by TEXT NOT NULL DEFAULT '',
    nuked_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    users_affected INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    total_credits_removed INTEGER NOT NULL DEFAULT 0,
    nukees TEXT NOT NULL DEFAULT '',
    nukees_data TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    unnuked_by TEXT NOT NULL DEFAULT '',
    unnuked_at INTEGER NOT NULL DEFAULT 0,
    restored_path TEXT NOT NULL DEFAULT '',
    total_credits_restored INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_nukes_original_path ON nukes(original_path);
CREATE INDEX IF NOT EXISTS idx_nukes_current_path ON nukes(current_path);
CREATE INDEX IF NOT EXISTS idx_nukes_release_name ON nukes(release_name);
CREATE INDEX IF NOT EXISTS idx_nukes_status ON nukes(status);
CREATE INDEX IF NOT EXISTS idx_nukes_nuked_at ON nukes(nuked_at DESC);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init nuke db schema: %w", err)
	}
	// Additive migration for DBs created before nukees_data existed. ADD COLUMN
	// on an existing table errors with "duplicate column name"; ignore only that.
	if _, err := db.Exec(`ALTER TABLE nukes ADD COLUMN nukees_data TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		db.Close()
		return nil, fmt.Errorf("migrate nuke db nukees_data: %w", err)
	}
	return &NukeHistoryDB{db: db, debug: debug}, nil
}

func (n *NukeHistoryDB) RecordNuke(entry NukeHistoryEntry) error {
	if n == nil || n.db == nil {
		return fmt.Errorf("nuke db unavailable")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if entry.NukedAt <= 0 {
		entry.NukedAt = time.Now().Unix()
	}
	if strings.TrimSpace(entry.CurrentPath) == "" {
		entry.CurrentPath = entry.OriginalPath
	}
	if strings.TrimSpace(entry.ReleaseName) == "" {
		entry.ReleaseName = path.Base(strings.TrimSpace(entry.OriginalPath))
	}
	if strings.TrimSpace(entry.Status) == "" {
		entry.Status = "active"
	}
	_, err := n.db.Exec(`
		INSERT INTO nukes(
			original_path, current_path, release_name, multiplier, reason, nuked_by,
			nuked_at, users_affected, total_bytes, total_credits_removed, nukees, nukees_data, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cleanNukePath(entry.OriginalPath), cleanNukePath(entry.CurrentPath), strings.TrimSpace(entry.ReleaseName),
		entry.Multiplier, strings.TrimSpace(entry.Reason), strings.TrimSpace(entry.NukedBy), entry.NukedAt,
		entry.UsersAffected, entry.TotalBytes, entry.TotalCreditsRemoved, strings.TrimSpace(entry.Nukees),
		strings.TrimSpace(entry.NukeesData), strings.TrimSpace(entry.Status))
	return err
}

func (n *NukeHistoryDB) FindActiveByPath(dirPath string) (*NukeHistoryEntry, error) {
	if n == nil || n.db == nil {
		return nil, fmt.Errorf("nuke db unavailable")
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	dirPath = cleanNukePath(dirPath)
	row := n.db.QueryRow(`
		SELECT id, original_path, current_path, release_name, multiplier, reason, nuked_by,
		       nuked_at, users_affected, total_bytes, total_credits_removed, nukees, nukees_data, status,
		       unnuked_by, unnuked_at, restored_path, total_credits_restored
		FROM nukes
		WHERE status = 'active' AND (current_path = ? OR original_path = ?)
		ORDER BY nuked_at DESC, id DESC
		LIMIT 1
	`, dirPath, dirPath)
	return scanNukeHistoryEntry(row)
}

func (n *NukeHistoryDB) MarkUnnuked(nukedPath, restoredPath, unnukedBy string, creditsRestored int64) (*NukeHistoryEntry, error) {
	if n == nil || n.db == nil {
		return nil, fmt.Errorf("nuke db unavailable")
	}
	entry, err := n.FindActiveByPath(nukedPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, sql.ErrNoRows
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, err = n.db.Exec(`
		UPDATE nukes
		SET status = 'unnuked',
		    unnuked_by = ?,
		    unnuked_at = ?,
		    restored_path = ?,
		    total_credits_restored = ?
		WHERE id = ?
	`, strings.TrimSpace(unnukedBy), time.Now().Unix(), cleanNukePath(restoredPath), creditsRestored, entry.ID)
	if err != nil {
		return nil, err
	}
	entry.Status = "unnuked"
	entry.UnnukedBy = strings.TrimSpace(unnukedBy)
	entry.UnnukedAt = time.Now().Unix()
	entry.RestoredPath = cleanNukePath(restoredPath)
	entry.TotalCreditsRestored = creditsRestored
	return entry, nil
}

func (n *NukeHistoryDB) MarkDeleted(nukedPath string) (*NukeHistoryEntry, error) {
	if n == nil || n.db == nil {
		return nil, fmt.Errorf("nuke db unavailable")
	}
	entry, err := n.FindActiveByPath(nukedPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, sql.ErrNoRows
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, err = n.db.Exec(`
		UPDATE nukes
		SET status = 'deleted'
		WHERE id = ?
	`, entry.ID)
	if err != nil {
		return nil, err
	}
	entry.Status = "deleted"
	return entry, nil
}

func (n *NukeHistoryDB) List(filter string, limit int) ([]NukeHistoryEntry, error) {
	if n == nil || n.db == nil {
		return nil, fmt.Errorf("nuke db unavailable")
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	query := `
		SELECT id, original_path, current_path, release_name, multiplier, reason, nuked_by,
		       nuked_at, users_affected, total_bytes, total_credits_removed, nukees, nukees_data, status,
		       unnuked_by, unnuked_at, restored_path, total_credits_restored
		FROM nukes
		WHERE status != 'deleted'
	`
	args := []interface{}{}
	if filter != "" {
		like := "%" + filter + "%"
		query += `
		AND (LOWER(original_path) LIKE ? OR LOWER(current_path) LIKE ? OR LOWER(release_name) LIKE ?
		   OR LOWER(reason) LIKE ? OR LOWER(nuked_by) LIKE ? OR LOWER(nukees) LIKE ?)
		`
		args = append(args, like, like, like, like, like, like)
	}
	query += ` ORDER BY nuked_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := n.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NukeHistoryEntry
	for rows.Next() {
		var entry NukeHistoryEntry
		if err := rows.Scan(
			&entry.ID, &entry.OriginalPath, &entry.CurrentPath, &entry.ReleaseName, &entry.Multiplier,
			&entry.Reason, &entry.NukedBy, &entry.NukedAt, &entry.UsersAffected, &entry.TotalBytes,
			&entry.TotalCreditsRemoved, &entry.Nukees, &entry.NukeesData, &entry.Status, &entry.UnnukedBy,
			&entry.UnnukedAt, &entry.RestoredPath, &entry.TotalCreditsRestored,
		); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func scanNukeHistoryEntry(row *sql.Row) (*NukeHistoryEntry, error) {
	var entry NukeHistoryEntry
	err := row.Scan(
		&entry.ID, &entry.OriginalPath, &entry.CurrentPath, &entry.ReleaseName, &entry.Multiplier,
		&entry.Reason, &entry.NukedBy, &entry.NukedAt, &entry.UsersAffected, &entry.TotalBytes,
		&entry.TotalCreditsRemoved, &entry.Nukees, &entry.NukeesData, &entry.Status, &entry.UnnukedBy,
		&entry.UnnukedAt, &entry.RestoredPath, &entry.TotalCreditsRestored,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func cleanNukePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return path.Clean("/" + p)
}
