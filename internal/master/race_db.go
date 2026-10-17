package master

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"weaveftpd/internal/core"
)

type RaceDB struct {
	db             *sql.DB
	listingDB      *sql.DB
	releaseIDCache sync.Map
}

const raceDBListingTimeout = 50 * time.Millisecond

type ReleaseFileRecord struct {
	FileName   string
	Owner      string
	Group      string
	SizeBytes  int64
	DurationMs int64
	Checksum   uint32
}

func NewRaceDB(dbPath string) (*RaceDB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create race db dir: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open race db: %w", err)
	}
	// SQLite only allows one writer at a time anyway. Keeping database/sql on a
	// single shared connection avoids self-inflicted write contention under heavy
	// passthrough/race churn where many goroutines record uploads/deletes at once.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA cache_size = -32000;",
	}
	for _, stmt := range pragmas {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("init pragma %q: %w", stmt, err)
		}
	}

	schema := `
CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    sfv_name TEXT NOT NULL DEFAULT '',
    total_expected INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS release_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    uploader TEXT NOT NULL DEFAULT '',
    grp TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    checksum INTEGER NOT NULL DEFAULT 0,
    expected_crc32 INTEGER NOT NULL DEFAULT 0,
    is_expected INTEGER NOT NULL DEFAULT 0,
    is_present INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(release_id, filename),
    FOREIGN KEY(release_id) REFERENCES releases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_release_files_release_id ON release_files(release_id);
CREATE INDEX IF NOT EXISTS idx_release_files_expected ON release_files(release_id, is_expected, filename);
CREATE INDEX IF NOT EXISTS idx_release_files_present ON release_files(release_id, is_present, filename);
CREATE INDEX IF NOT EXISTS idx_release_files_uploader_present ON release_files(release_id, uploader, is_present);
CREATE INDEX IF NOT EXISTS idx_release_files_group_present ON release_files(release_id, grp, is_present);
CREATE INDEX IF NOT EXISTS idx_releases_path ON releases(path);

CREATE TABLE IF NOT EXISTS release_media (
    release_id INTEGER NOT NULL,
    field_key TEXT NOT NULL,
    field_value TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(release_id, field_key),
    FOREIGN KEY(release_id) REFERENCES releases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_release_media_release_id ON release_media(release_id);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init race db schema: %w", err)
	}

	// Optional listing repairs must not queue behind upload transactions. WAL
	// permits this reader to see committed data while the writer is occupied.
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("resolve race db path: %w", err)
	}
	uriPath := filepath.ToSlash(absPath)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	readerURI := url.URL{Scheme: "file", Path: uriPath}
	readerURI.RawQuery = url.Values{"mode": {"ro"}, "_busy_timeout": {"0"}, "_query_only": {"1"}}.Encode()
	listingDB, err := sql.Open("sqlite3", readerURI.String())
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open race db listing reader: %w", err)
	}
	listingDB.SetMaxOpenConns(1)
	listingDB.SetMaxIdleConns(1)
	if err := listingDB.Ping(); err != nil {
		listingDB.Close()
		db.Close()
		return nil, fmt.Errorf("init race db listing reader: %w", err)
	}
	return &RaceDB{db: db, listingDB: listingDB}, nil
}

func (r *RaceDB) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	var readerErr error
	if r.listingDB != nil {
		readerErr = r.listingDB.Close()
	}
	return errors.Join(readerErr, r.db.Close())
}

func (r *RaceDB) getOrCreateReleaseID(dirPath string) (int64, error) {
	dirPath = filepath.Clean(dirPath)
	if cached, ok := r.cachedReleaseID(dirPath); ok {
		return cached, nil
	}

	tx, err := r.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
        INSERT INTO releases(path, created_at, updated_at)
        VALUES (?, strftime('%s','now'), strftime('%s','now'))
        ON CONFLICT(path) DO UPDATE SET updated_at = strftime('%s','now')
    `, dirPath); err != nil {
		return 0, err
	}

	var releaseID int64
	if err := tx.QueryRow(`SELECT id FROM releases WHERE path = ?`, dirPath).Scan(&releaseID); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	r.cacheReleaseID(dirPath, releaseID)
	return releaseID, nil
}

func (r *RaceDB) cachedReleaseID(dirPath string) (int64, bool) {
	if r == nil {
		return 0, false
	}
	if value, ok := r.releaseIDCache.Load(filepath.Clean(dirPath)); ok {
		if releaseID, ok := value.(int64); ok && releaseID > 0 {
			return releaseID, true
		}
	}
	return 0, false
}

func (r *RaceDB) cacheReleaseID(dirPath string, releaseID int64) {
	if r == nil || releaseID <= 0 {
		return
	}
	r.releaseIDCache.Store(filepath.Clean(dirPath), releaseID)
}

func (r *RaceDB) invalidateReleaseID(dirPath string) {
	if r == nil {
		return
	}
	r.releaseIDCache.Delete(filepath.Clean(dirPath))
}

func (r *RaceDB) invalidateReleaseIDPrefix(dirPath string) {
	if r == nil {
		return
	}
	dirPath = filepath.Clean(dirPath)
	prefix := dirPath + string(filepath.Separator)
	r.releaseIDCache.Range(func(key, _ interface{}) bool {
		cachedPath, ok := key.(string)
		if ok && (cachedPath == dirPath || strings.HasPrefix(cachedPath, prefix)) {
			r.releaseIDCache.Delete(cachedPath)
		}
		return true
	})
}

func (r *RaceDB) SaveSFV(dirPath, sfvName string, entries map[string]uint32) error {
	releaseID, err := r.getOrCreateReleaseID(dirPath)
	if err != nil {
		return err
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
        UPDATE releases
        SET sfv_name = ?, total_expected = ?, updated_at = strftime('%s','now')
        WHERE id = ?
    `, sfvName, len(entries), releaseID); err != nil {
		return err
	}

	for fileName, crc := range entries {
		fileName = raceDBFileKey(fileName)
		if fileName == "" {
			continue
		}
		if _, err := tx.Exec(`
            INSERT INTO release_files(
                release_id, filename, expected_crc32, is_expected, updated_at
            ) VALUES (?, ?, ?, 1, strftime('%s','now'))
            ON CONFLICT(release_id, filename) DO UPDATE SET
                expected_crc32 = excluded.expected_crc32,
                is_expected = 1,
                updated_at = strftime('%s','now')
        `, releaseID, fileName, int64(crc)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *RaceDB) SaveMediaInfo(dirPath string, fields map[string]string) error {
	releaseID, err := r.getOrCreateReleaseID(dirPath)
	if err != nil {
		return err
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM release_media WHERE release_id = ?`, releaseID); err != nil {
		return err
	}

	for key, value := range fields {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if _, err := tx.Exec(`
            INSERT INTO release_media(release_id, field_key, field_value)
            VALUES (?, ?, ?)
        `, releaseID, key, value); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *RaceDB) RecordUpload(filePath, owner, group string, size int64, durationMs int64, checksum uint32) error {
	dirPath := filepath.Dir(filePath)
	fileName := raceDBFileKey(filepath.Base(filePath))
	if fileName == "" {
		return nil
	}

	releaseID, err := r.getOrCreateReleaseID(dirPath)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
        INSERT INTO release_files(
            release_id, filename, uploader, grp, size_bytes, duration_ms,
            checksum, is_present, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, strftime('%s','now'))
        ON CONFLICT(release_id, filename) DO UPDATE SET
            uploader = excluded.uploader,
            grp = excluded.grp,
            size_bytes = excluded.size_bytes,
            duration_ms = excluded.duration_ms,
            checksum = excluded.checksum,
            is_present = 1,
            updated_at = strftime('%s','now')
        WHERE release_files.is_present = 0
           OR trim(release_files.uploader) = ''
           OR lower(trim(release_files.uploader)) IN ('weaveftpd', 'ftp', 'root', '0')
    `, releaseID, fileName, owner, group, size, durationMs, int64(checksum))
	return err
}

func (r *RaceDB) ReplaceReleaseFiles(dirPath, sfvName string, entries map[string]uint32, files map[string]ReleaseFileRecord) error {
	if r == nil || r.db == nil {
		return nil
	}
	dirPath = filepath.Clean(dirPath)
	if len(entries) == 0 {
		return nil
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
        INSERT INTO releases(path, created_at, updated_at)
        VALUES (?, strftime('%s','now'), strftime('%s','now'))
        ON CONFLICT(path) DO UPDATE SET updated_at = strftime('%s','now')
    `, dirPath); err != nil {
		return err
	}

	var releaseID int64
	if err := tx.QueryRow(`SELECT id FROM releases WHERE path = ?`, dirPath).Scan(&releaseID); err != nil {
		return err
	}

	existingFiles, err := existingReleaseFilesTx(tx, releaseID)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`
        UPDATE releases
        SET sfv_name = ?, total_expected = ?, updated_at = strftime('%s','now')
        WHERE id = ?
    `, sfvName, len(entries), releaseID); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM release_files WHERE release_id = ?`, releaseID); err != nil {
		return err
	}

	fileNames := make([]string, 0, len(entries))
	for fileName := range entries {
		fileNames = append(fileNames, fileName)
	}
	sort.Strings(fileNames)

	for _, rawName := range fileNames {
		fileName := raceDBFileKey(rawName)
		if fileName == "" {
			continue
		}
		expectedCRC := int64(entries[rawName])
		record, ok := files[fileName]
		if !ok {
			if _, err := tx.Exec(`
                INSERT INTO release_files(
                    release_id, filename, expected_crc32, is_expected, is_present, updated_at
                ) VALUES (?, ?, ?, 1, 0, strftime('%s','now'))
            `, releaseID, fileName, expectedCRC); err != nil {
				return err
			}
			continue
		}
		if existing, ok := existingFiles[fileName]; ok {
			record = mergeRaceFileRecord(record, existing)
		}
		if _, err := tx.Exec(`
            INSERT INTO release_files(
                release_id, filename, uploader, grp, size_bytes, duration_ms,
                checksum, expected_crc32, is_expected, is_present, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, strftime('%s','now'))
        `, releaseID, fileName, record.Owner, record.Group, record.SizeBytes, record.DurationMs, int64(record.Checksum), expectedCRC); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func existingReleaseFilesTx(tx *sql.Tx, releaseID int64) (map[string]ReleaseFileRecord, error) {
	rows, err := tx.Query(`
        SELECT filename, uploader, grp, size_bytes, duration_ms, checksum
        FROM release_files
        WHERE release_id = ? AND is_present = 1
    `, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]ReleaseFileRecord)
	for rows.Next() {
		var rec ReleaseFileRecord
		var checksum int64
		if err := rows.Scan(&rec.FileName, &rec.Owner, &rec.Group, &rec.SizeBytes, &rec.DurationMs, &checksum); err != nil {
			return nil, err
		}
		rec.FileName = raceDBFileKey(rec.FileName)
		rec.Checksum = uint32(checksum)
		if rec.FileName != "" {
			out[rec.FileName] = rec
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *RaceDB) VerifiedPresentFiles(dirPath string) (map[string]ReleaseFileRecord, error) {
	if r == nil || r.listingDB == nil {
		return nil, nil
	}
	// This also bounds waiting for another listing to release the reader. A
	// context alone would not avoid SQLite's five-second writer busy handler.
	ctx, cancel := context.WithTimeout(context.Background(), raceDBListingTimeout)
	defer cancel()
	dirPath = filepath.Clean(dirPath)
	rows, err := r.listingDB.QueryContext(ctx, `
        SELECT p.filename, p.uploader, p.grp, p.size_bytes, p.duration_ms, p.checksum
        FROM releases r
        JOIN release_files p
          ON p.release_id = r.id
        LEFT JOIN release_files e
          ON e.release_id = p.release_id
         AND e.is_expected = 1
         AND e.filename = p.filename
        WHERE r.path = ?
          AND p.is_present = 1
          AND p.duration_ms > 0
          AND (e.id IS NULL OR p.checksum = e.expected_crc32)
    `, dirPath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]ReleaseFileRecord)
	for rows.Next() {
		var rec ReleaseFileRecord
		var checksum int64
		if err := rows.Scan(&rec.FileName, &rec.Owner, &rec.Group, &rec.SizeBytes, &rec.DurationMs, &checksum); err != nil {
			return nil, err
		}
		rec.FileName = raceDBFileKey(rec.FileName)
		rec.Checksum = uint32(checksum)
		if rec.FileName != "" {
			out[rec.FileName] = rec
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func mergeRaceFileRecord(next, existing ReleaseFileRecord) ReleaseFileRecord {
	if isWeakMetadataValue(next.Owner) && !isWeakMetadataValue(existing.Owner) {
		next.Owner = existing.Owner
	}
	if isWeakMetadataValue(next.Group) && !isWeakMetadataValue(existing.Group) {
		next.Group = existing.Group
	}
	if next.SizeBytes <= 0 && existing.SizeBytes > 0 {
		next.SizeBytes = existing.SizeBytes
	}
	if next.DurationMs <= 0 && existing.DurationMs > 0 {
		next.DurationMs = existing.DurationMs
	}
	if next.Checksum == 0 && existing.Checksum != 0 {
		next.Checksum = existing.Checksum
	}
	return next
}

func (r *RaceDB) DeletePath(path string, isDir bool) error {
	if isDir {
		_, err := r.db.Exec(`DELETE FROM releases WHERE path = ? OR path LIKE ?`, path, path+"/%")
		if err == nil {
			r.invalidateReleaseIDPrefix(path)
		}
		return err
	}

	dirPath := filepath.Dir(path)
	fileName := raceDBFileKey(filepath.Base(path))
	_, err := r.db.Exec(`
        UPDATE release_files
        SET is_present = 0,
            size_bytes = 0,
            duration_ms = 0,
            checksum = 0,
            updated_at = strftime('%s','now')
        WHERE release_id = (SELECT id FROM releases WHERE path = ?)
          AND filename = ?
    `, dirPath, fileName)
	return err
}

func (r *RaceDB) RenamePath(from, to string, isDir bool) error {
	if isDir {
		tx, err := r.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		rows, err := tx.Query(`SELECT path FROM releases WHERE path = ? OR path LIKE ?`, from, from+"/%")
		if err != nil {
			return err
		}
		defer rows.Close()

		var paths []string
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				return err
			}
			paths = append(paths, p)
		}
		sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })

		for _, oldPath := range paths {
			newPath := to + oldPath[len(from):]
			if _, err := tx.Exec(`UPDATE releases SET path = ?, updated_at = strftime('%s','now') WHERE path = ?`, newPath, oldPath); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		r.invalidateReleaseIDPrefix(from)
		return nil
	}

	oldDir, oldName := filepath.Dir(from), filepath.Base(from)
	newDir, newName := filepath.Dir(to), filepath.Base(to)
	oldName = raceDBFileKey(oldName)
	newName = raceDBFileKey(newName)

	oldReleaseID, err := r.getOrCreateReleaseID(oldDir)
	if err != nil {
		return err
	}
	newReleaseID, err := r.getOrCreateReleaseID(newDir)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
        UPDATE release_files
        SET release_id = ?, filename = ?, updated_at = strftime('%s','now')
        WHERE release_id = ? AND filename = ?
    `, newReleaseID, newName, oldReleaseID, oldName)
	return err
}

func (r *RaceDB) ScrubReleaseRaceMetadata(dirPath, owner, group string) error {
	if r == nil || r.db == nil {
		return nil
	}
	dirPath = filepath.Clean(dirPath)
	owner = strings.TrimSpace(owner)
	group = strings.TrimSpace(group)
	_, err := r.db.Exec(`
        UPDATE release_files
        SET uploader = ?,
            grp = ?,
            duration_ms = 0,
            updated_at = strftime('%s','now')
        WHERE release_id IN (
            SELECT id FROM releases WHERE path = ? OR path LIKE ?
        )
    `, owner, group, dirPath, dirPath+"/%")
	return err
}

func (r *RaceDB) Reconcile(vfs *VirtualFileSystem) error {
	releaseRows, err := r.db.Query(`SELECT path FROM releases`)
	if err != nil {
		return err
	}
	var stale []string
	for releaseRows.Next() {
		var dirPath string
		if err := releaseRows.Scan(&dirPath); err != nil {
			releaseRows.Close()
			return err
		}
		file := vfs.GetFile(dirPath)
		if file == nil || !file.IsDir {
			stale = append(stale, dirPath)
		}
	}
	if err := releaseRows.Err(); err != nil {
		releaseRows.Close()
		return err
	}
	releaseRows.Close()
	for _, dirPath := range stale {
		if _, err := r.db.Exec(`DELETE FROM releases WHERE path = ?`, dirPath); err != nil {
			return err
		}
		r.invalidateReleaseID(dirPath)
	}

	return nil
}

func (r *RaceDB) GetMediaInfo(dirPath string) map[string]string {
	if r == nil || r.db == nil {
		return nil
	}
	rows, err := r.db.Query(`
        SELECT rm.field_key, rm.field_value
        FROM releases rel
        JOIN release_media rm ON rm.release_id = rel.id
        WHERE rel.path = ?
        ORDER BY rm.field_key
    `, dirPath)
	if err != nil {
		log.Printf("[RaceDB] media probe query failed for %s: %v", dirPath, err)
		return nil
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			log.Printf("[RaceDB] media probe row scan failed for %s: %v", dirPath, err)
			return nil
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("[RaceDB] media probe row iteration failed for %s: %v", dirPath, err)
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (r *RaceDB) GetRaceStats(dirPath string) ([]core.VFSRaceUser, []core.VFSRaceGroup, int64, int, int) {
	var releaseID int64
	var total int
	err := r.db.QueryRow(`SELECT id, total_expected FROM releases WHERE path = ?`, dirPath).Scan(&releaseID, &total)
	if err == sql.ErrNoRows {
		return nil, nil, 0, 0, 0
	}
	if err != nil {
		log.Printf("[RaceDB] release lookup failed for %s: %v", dirPath, err)
		return nil, nil, 0, 0, 0
	}
	if total <= 0 {
		return nil, nil, 0, 0, 0
	}

	var present int
	var totalBytes int64
	if err := r.db.QueryRow(`
        SELECT COALESCE(COUNT(*), 0), COALESCE(SUM(size_bytes), 0)
        FROM (
            SELECT e.filename, MAX(p.size_bytes) AS size_bytes
            FROM release_files e
            JOIN release_files p
              ON p.release_id = e.release_id
             AND p.is_present = 1
             AND p.filename = e.filename
             AND p.checksum = e.expected_crc32
            WHERE e.release_id = ?
              AND e.is_expected = 1
            GROUP BY e.filename
        )
    `, releaseID).Scan(&present, &totalBytes); err != nil {
		log.Printf("[RaceDB] present query failed for %s: %v", dirPath, err)
		return nil, nil, 0, 0, 0
	}

	userRows, err := r.db.Query(`
        WITH valid_present AS (
            SELECT p.*
            FROM release_files p
            JOIN release_files e
              ON e.release_id = p.release_id
             AND e.is_expected = 1
             AND e.filename = p.filename
            WHERE p.release_id = ?
              AND p.is_present = 1
              AND p.duration_ms > 0
              AND p.checksum = e.expected_crc32
        )
        SELECT
            uploader,
            grp,
            COUNT(*),
            COALESCE(SUM(size_bytes),0),
            COALESCE(SUM(duration_ms),0),
            COALESCE(MIN((updated_at * 1000) - duration_ms), 0),
            COALESCE(MAX(updated_at * 1000), 0),
            COALESCE(MAX(CAST(size_bytes AS REAL) / CAST(duration_ms AS REAL)), 0),
            COALESCE(MIN(CAST(size_bytes AS REAL) / CAST(duration_ms AS REAL)), 0)
        FROM valid_present
        GROUP BY uploader, grp
        ORDER BY COALESCE(SUM(size_bytes),0) DESC, COUNT(*) DESC, uploader ASC
    `, releaseID)
	if err != nil {
		log.Printf("[RaceDB] user stats query failed for %s: %v", dirPath, err)
		return nil, nil, 0, 0, 0
	}
	defer userRows.Close()

	var users []core.VFSRaceUser
	var userDurations []int64
	var userStartMs []int64
	var userEndMs []int64
	var userPeakRates []float64
	var userSlowRates []float64
	for userRows.Next() {
		var u core.VFSRaceUser
		var durationMs int64
		var startMs int64
		var endMs int64
		var peakRate float64
		var slowRate float64
		if err := userRows.Scan(&u.Name, &u.Group, &u.Files, &u.Bytes, &durationMs, &startMs, &endMs, &peakRate, &slowRate); err != nil {
			log.Printf("[RaceDB] user row scan failed for %s: %v", dirPath, err)
			return nil, nil, 0, 0, 0
		}
		users = append(users, u)
		userDurations = append(userDurations, durationMs)
		userStartMs = append(userStartMs, startMs)
		userEndMs = append(userEndMs, endMs)
		userPeakRates = append(userPeakRates, peakRate)
		userSlowRates = append(userSlowRates, slowRate)
	}
	if err := userRows.Err(); err != nil {
		log.Printf("[RaceDB] user rows iteration failed for %s: %v", dirPath, err)
		return nil, nil, 0, 0, 0
	}
	_ = userRows.Close()

	for i := range users {
		u := &users[i]
		durationMs := userDurations[i]
		u.DurationMs = durationMs
		// pzs-ng: speed = bytes / sum(transfer time), excluding idle gaps
		// between a racer's files. Wall-clock span is only a fallback.
		if u.Bytes > 0 && durationMs > 0 {
			u.Speed = float64(u.Bytes) / (float64(durationMs) / 1000.0)
		} else if startMs, endMs := userStartMs[i], userEndMs[i]; u.Bytes > 0 && endMs > startMs {
			u.Speed = float64(u.Bytes) / (float64(endMs-startMs) / 1000.0)
		}
		u.PeakSpeed = userPeakRates[i] * 1000.0
		u.SlowSpeed = userSlowRates[i] * 1000.0
		if total > 0 {
			u.Percent = (u.Files * 100) / total
			if u.Percent > 100 {
				u.Percent = 100
			}
		}
	}

	groupRows, err := r.db.Query(`
        SELECT
            p.grp,
            COUNT(*),
            COALESCE(SUM(p.size_bytes),0)
        FROM release_files p
        JOIN release_files e
          ON e.release_id = p.release_id
         AND e.is_expected = 1
         AND e.filename = p.filename
        WHERE p.release_id = ?
          AND p.is_present = 1
          AND p.duration_ms > 0
          AND p.checksum = e.expected_crc32
        GROUP BY p.grp
        ORDER BY COALESCE(SUM(p.size_bytes),0) DESC, COUNT(*) DESC, p.grp ASC
    `, releaseID)
	if err != nil {
		log.Printf("[RaceDB] group stats query failed for %s: %v", dirPath, err)
		return nil, nil, 0, 0, 0
	}
	defer groupRows.Close()

	var groups []core.VFSRaceGroup
	for groupRows.Next() {
		var g core.VFSRaceGroup
		if err := groupRows.Scan(&g.Name, &g.Files, &g.Bytes); err != nil {
			log.Printf("[RaceDB] group row scan failed for %s: %v", dirPath, err)
			return nil, nil, 0, 0, 0
		}
		// pzs-ng: group speed = group bytes / sum(group transfer time).
		var groupDurationMs int64
		for _, u := range users {
			if u.Group != g.Name {
				continue
			}
			groupDurationMs += u.DurationMs
		}
		if g.Bytes > 0 && groupDurationMs > 0 {
			g.Speed = float64(g.Bytes) / (float64(groupDurationMs) / 1000.0)
		}
		if total > 0 {
			g.Percent = (g.Files * 100) / total
			if g.Percent > 100 {
				g.Percent = 100
			}
		}
		groups = append(groups, g)
	}

	if present > total {
		present = total
	}

	return users, groups, totalBytes, present, total
}

func (r *RaceDB) HydrateVFS(vfs *VirtualFileSystem) (int, error) {
	if r == nil || r.db == nil || vfs == nil {
		return 0, nil
	}

	rows, err := r.db.Query(`
        SELECT r.path, p.filename, p.uploader, p.grp, p.size_bytes, p.duration_ms, p.checksum
        FROM releases r
        JOIN release_files p
          ON p.release_id = r.id
        LEFT JOIN release_files e
          ON e.release_id = p.release_id
         AND e.is_expected = 1
         AND e.filename = p.filename
        WHERE p.is_present = 1
          AND p.duration_ms > 0
          AND (e.id IS NULL OR p.checksum = e.expected_crc32)
    `)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	hydrated := 0
	for rows.Next() {
		var dirPath, fileName, owner, group string
		var sizeBytes int64
		var durationMs int64
		var checksum int64
		if err := rows.Scan(&dirPath, &fileName, &owner, &group, &sizeBytes, &durationMs, &checksum); err != nil {
			return hydrated, err
		}
		filePath := filepath.ToSlash(path.Join(dirPath, fileName))
		if vfs.HydrateRaceFile(filePath, owner, group, sizeBytes, durationMs, uint32(checksum)) {
			hydrated++
		}
	}
	if err := rows.Err(); err != nil {
		return hydrated, err
	}
	return hydrated, nil
}

func (r *RaceDB) HasRelease(dirPath string) bool {
	if r == nil || r.db == nil {
		return false
	}
	var one int
	err := r.db.QueryRow(`SELECT 1 FROM releases WHERE path = ? LIMIT 1`, dirPath).Scan(&one)
	return err == nil && one == 1
}

func raceDBFileKey(name string) string {
	name = strings.TrimSpace(filepath.ToSlash(name))
	name = strings.TrimPrefix(name, "./")
	return strings.ToLower(name)
}

// GetRaceWallClockMilliseconds returns the wall-clock duration of a release
// race in milliseconds. SQLite timestamps here are second-granular, so use each
// file's stored duration_ms to reconstruct the earliest transfer start. This
// keeps very fast races from being rounded up to 1s.
func (r *RaceDB) GetRaceWallClockMilliseconds(dirPath string) int64 {
	if r == nil || r.db == nil {
		return 0
	}
	var startMs, endMs sql.NullInt64
	err := r.db.QueryRow(`
        SELECT
            COALESCE(
                (
                    SELECT MIN(CASE
                        WHEN f.duration_ms > 0 THEN (f.updated_at * 1000) - f.duration_ms
                        ELSE rel.created_at * 1000
                    END)
                    FROM release_files f
                    WHERE f.release_id = rel.id AND f.is_present = 1 AND f.is_expected = 1
                ),
                (
                    SELECT MIN(CASE
                        WHEN f.duration_ms > 0 THEN (f.updated_at * 1000) - f.duration_ms
                        ELSE rel.created_at * 1000
                    END)
                    FROM release_files f
                    WHERE f.release_id = rel.id AND f.is_present = 1
                ),
                rel.created_at * 1000
            ),
            COALESCE(
                (
                    SELECT MAX(f.updated_at * 1000)
                    FROM release_files f
                    WHERE f.release_id = rel.id AND f.is_present = 1 AND f.is_expected = 1
                ),
                (
                    SELECT MAX(f.updated_at * 1000)
                    FROM release_files f
                    WHERE f.release_id = rel.id AND f.is_present = 1
                ),
                rel.created_at * 1000
            )
        FROM releases rel
        WHERE rel.path = ?
    `, dirPath).Scan(&startMs, &endMs)
	if err != nil || !startMs.Valid || !endMs.Valid {
		return 0
	}
	d := endMs.Int64 - startMs.Int64
	if d < 1 {
		d = 1
	}
	return d
}

func (r *RaceDB) SearchDirs(query string, limit int) []core.VFSSearchResult {
	if r == nil || r.db == nil {
		return nil
	}

	tokens := searchTokens(query)
	if len(tokens) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}

	where := make([]string, 0, len(tokens))
	args := make([]interface{}, 0, len(tokens)+1)
	for _, token := range tokens {
		where = append(where, "LOWER(rel.path) LIKE ?")
		args = append(args, "%"+token+"%")
	}
	args = append(args, limit)

	rows, err := r.db.Query(`
        SELECT
            rel.path,
            COALESCE(SUM(CASE WHEN rf.is_present = 1 THEN 1 ELSE 0 END), 0) AS present_files,
            COALESCE(SUM(CASE WHEN rf.is_present = 1 THEN rf.size_bytes ELSE 0 END), 0) AS present_bytes,
            MAX(
                COALESCE(
                    CASE WHEN rf.updated_at > 0 THEN rf.updated_at END,
                    rel.updated_at,
                    rel.created_at
                )
            ) AS mod_time
        FROM releases rel
        LEFT JOIN release_files rf ON rf.release_id = rel.id
        WHERE `+strings.Join(where, " AND ")+`
        GROUP BY rel.id, rel.path
        ORDER BY LOWER(rel.path) ASC
        LIMIT ?
    `, args...)
	if err != nil {
		log.Printf("[RaceDB] search query failed for %q: %v", query, err)
		return nil
	}
	defer rows.Close()

	results := make([]core.VFSSearchResult, 0, limit)
	for rows.Next() {
		var res core.VFSSearchResult
		if err := rows.Scan(&res.Path, &res.Files, &res.Bytes, &res.ModTime); err != nil {
			log.Printf("[RaceDB] search row scan failed for %q: %v", query, err)
			return nil
		}
		results = append(results, res)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[RaceDB] search rows iteration failed for %q: %v", query, err)
		return nil
	}
	return results
}

func searchTokens(query string) []string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	if len(fields) == 0 {
		return nil
	}
	tokens := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if field == "" {
			continue
		}
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		tokens = append(tokens, field)
	}
	return tokens
}
