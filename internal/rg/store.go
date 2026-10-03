package rg

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Ban struct {
	IP        string
	Reason    string
	Detail    string
	CreatedAt int64
	ExpiresAt int64
	Intensity sql.NullFloat64
}

type Reputation struct {
	IP        string
	Score     int
	CheckedAt int64
	ExpiresAt int64
	Detail    string
	Country   string
}

type Store struct {
	mu sync.Mutex
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	if path != ":memory:" {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
		}
	}
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=busy_timeout(3000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS bans (
			ip TEXT PRIMARY KEY,
			reason TEXT NOT NULL,
			detail TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			intensity REAL
		);
		CREATE TABLE IF NOT EXISTS reputation (
			ip TEXT PRIMARY KEY,
			score INTEGER NOT NULL,
			checked_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			detail TEXT NOT NULL,
			country TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);
		CREATE INDEX IF NOT EXISTS idx_reputation_expires ON reputation(expires_at);
	`)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := ensureCountry(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func ensureCountry(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(reputation)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "country" {
			return nil
		}
	}
	_, err = db.Exec(`ALTER TABLE reputation ADD COLUMN country TEXT NOT NULL DEFAULT ''`)
	return err
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *Store) Ban(ip, reason string, days int, now time.Time, detail string, intensity sql.NullFloat64, expiresAt *int64) (Ban, bool, error) {
	nowTS := now.Unix()
	newExpires := nowTS + int64(days)*86400
	if expiresAt != nil {
		newExpires = *expiresAt
	}
	detail = clip(detail, 200)
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT ip, reason, detail, created_at, expires_at, intensity FROM bans WHERE ip = ?`, ip)
	existing, err := scanBan(row)
	active := err == nil && existing.ExpiresAt > nowTS
	if err != nil && err != sql.ErrNoRows {
		return Ban{}, false, err
	}
	if active && existing.ExpiresAt >= newExpires {
		return existing, false, nil
	}
	created := nowTS
	if active {
		created = existing.CreatedAt
	}
	var intensityVal any
	if intensity.Valid {
		intensityVal = intensity.Float64
	}
	_, err = s.db.Exec(`
		INSERT INTO bans (ip, reason, detail, created_at, expires_at, intensity)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			reason = excluded.reason,
			detail = excluded.detail,
			created_at = excluded.created_at,
			expires_at = excluded.expires_at,
			intensity = excluded.intensity
	`, ip, reason, detail, created, newExpires, intensityVal)
	if err != nil {
		return Ban{}, false, err
	}
	savedRow := s.db.QueryRow(`SELECT ip, reason, detail, created_at, expires_at, intensity FROM bans WHERE ip = ?`, ip)
	saved, err := scanBan(savedRow)
	return saved, true, err
}

func (s *Store) GetBan(ip string, now time.Time) (*Ban, error) {
	nowTS := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT ip, reason, detail, created_at, expires_at, intensity FROM bans WHERE ip = ?`, ip)
	ban, err := scanBan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ban.ExpiresAt <= nowTS {
		_, _ = s.db.Exec(`DELETE FROM bans WHERE ip = ?`, ip)
		return nil, nil
	}
	return &ban, nil
}

func (s *Store) ListBans(now time.Time) ([]Ban, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT ip, reason, detail, created_at, expires_at, intensity FROM bans WHERE expires_at > ? ORDER BY expires_at DESC`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		ban, err := scanBanRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ban)
	}
	return out, rows.Err()
}

func (s *Store) SaveReputation(ip string, score int, now time.Time, days int, detail, country string) error {
	nowTS := now.Unix()
	expires := nowTS + int64(days)*86400
	detail = clip(detail, 200)
	country = clip(country, 8)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO reputation (ip, score, checked_at, expires_at, detail, country)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			score = excluded.score,
			checked_at = excluded.checked_at,
			expires_at = excluded.expires_at,
			detail = excluded.detail,
			country = excluded.country
	`, ip, score, nowTS, expires, detail, country)
	return err
}

func (s *Store) GetReputation(ip string, now time.Time) (*Reputation, error) {
	nowTS := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT ip, score, checked_at, expires_at, detail, country FROM reputation WHERE ip = ?`, ip)
	var rep Reputation
	err := row.Scan(&rep.IP, &rep.Score, &rep.CheckedAt, &rep.ExpiresAt, &rep.Detail, &rep.Country)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rep.ExpiresAt <= nowTS {
		_, _ = s.db.Exec(`DELETE FROM reputation WHERE ip = ?`, ip)
		return nil, nil
	}
	return &rep, nil
}

func (s *Store) ListReputation(now time.Time) ([]Reputation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT ip, score, checked_at, expires_at, detail, country FROM reputation WHERE expires_at > ? ORDER BY checked_at DESC`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Reputation
	for rows.Next() {
		var rep Reputation
		if err := rows.Scan(&rep.IP, &rep.Score, &rep.CheckedAt, &rep.ExpiresAt, &rep.Detail, &rep.Country); err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, rows.Err()
}

func (s *Store) Purge(now time.Time) (int, error) {
	nowTS := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	bans, err := s.db.Exec(`DELETE FROM bans WHERE expires_at <= ?`, nowTS)
	if err != nil {
		return 0, err
	}
	reps, err := s.db.Exec(`DELETE FROM reputation WHERE expires_at <= ?`, nowTS)
	if err != nil {
		return 0, err
	}
	bn, _ := bans.RowsAffected()
	rn, _ := reps.RowsAffected()
	return int(bn + rn), nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanBan(row scanner) (Ban, error) {
	var ban Ban
	err := row.Scan(&ban.IP, &ban.Reason, &ban.Detail, &ban.CreatedAt, &ban.ExpiresAt, &ban.Intensity)
	return ban, err
}

func scanBanRows(rows *sql.Rows) (Ban, error) {
	return scanBan(rows)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
