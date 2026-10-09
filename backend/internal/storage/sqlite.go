package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Bigik7/integrasec-platform/backend/internal/model"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create DB directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite DB: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.Init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Init() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS machines (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			agent_key_hash TEXT NOT NULL,
			registered_utc TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id TEXT NOT NULL,
			path TEXT NOT NULL,
			type TEXT NOT NULL,
			old_hash TEXT,
			new_hash TEXT,
			timestamp_utc TEXT NOT NULL,
			severity TEXT NOT NULL,
			FOREIGN KEY(machine_id) REFERENCES machines(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_machine_timestamp ON events(machine_id, timestamp_utc DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("init schema failed: %w", err)
		}
	}
	return nil
}

func hashAgentKey(key string) string {
	s := sha256.Sum256([]byte(key))
	return hex.EncodeToString(s[:])
}

func (s *Store) RegisterMachine(machineID, hostname, agentKey string) error {
	_, err := s.db.Exec(`
		INSERT INTO machines(id, hostname, agent_key_hash, registered_utc)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname = excluded.hostname,
			agent_key_hash = excluded.agent_key_hash,
			registered_utc = excluded.registered_utc
	`, machineID, hostname, hashAgentKey(agentKey), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("register machine: %w", err)
	}
	return nil
}

func (s *Store) FindMachineByAgentKey(agentKey string) (string, bool, error) {
	row := s.db.QueryRow(`SELECT id FROM machines WHERE agent_key_hash = ? LIMIT 1`, hashAgentKey(agentKey))
	var machineID string
	if err := row.Scan(&machineID); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("find machine by key: %w", err)
	}
	return machineID, true, nil
}

func (s *Store) InsertEvents(events []model.IntegrityEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO events(machine_id, path, type, old_hash, new_hash, timestamp_utc, severity)
		VALUES(?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		if _, err := stmt.Exec(event.Machine, event.Path, event.Type, event.OldHash, event.NewHash, event.TimestampUTC, event.Severity); err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *Store) ListMachines() ([]model.Machine, error) {
	rows, err := s.db.Query(`SELECT id, hostname, registered_utc FROM machines ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer rows.Close()

	machines := make([]model.Machine, 0)
	for rows.Next() {
		var m model.Machine
		if err := rows.Scan(&m.ID, &m.Hostname, &m.RegisteredUTC); err != nil {
			return nil, fmt.Errorf("scan machine: %w", err)
		}
		machines = append(machines, m)
	}
	return machines, rows.Err()
}

func (s *Store) ListEvents(machineID, eventType string, limit int) ([]model.IntegrityEvent, error) {
	query := `SELECT machine_id, path, type, old_hash, new_hash, timestamp_utc, severity FROM events WHERE 1=1`
	args := make([]any, 0)
	if machineID != "" {
		query += ` AND machine_id = ?`
		args = append(args, machineID)
	}
	if eventType != "" {
		query += ` AND type = ?`
		args = append(args, eventType)
	}
	query += ` ORDER BY timestamp_utc DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	events := make([]model.IntegrityEvent, 0)
	for rows.Next() {
		var e model.IntegrityEvent
		if err := rows.Scan(&e.Machine, &e.Path, &e.Type, &e.OldHash, &e.NewHash, &e.TimestampUTC, &e.Severity); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
