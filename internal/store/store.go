// Package store persists devices and policy rules in SQLite.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/CYC07/cerberus/internal/policy"
)

// Store wraps a SQLite database of registered devices and policy rules.
type Store struct {
	db *sql.DB
}

// Device is a registered device's identity record.
type Device struct {
	DeviceID   string
	CertPEM    string
	CertSerial string
	Revoked    bool
}

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("store: not found")

// Open opens (creating if needed) the SQLite database at path and runs
// migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS devices (
	device_id TEXT PRIMARY KEY,
	enrollment_token TEXT,
	cert_pem TEXT,
	cert_serial TEXT,
	revoked INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subject TEXT NOT NULL,
	resource TEXT NOT NULL,
	action TEXT NOT NULL CHECK(action IN ('allow','deny')),
	UNIQUE(subject, resource)
);`)
	if err != nil {
		return err
	}
	return migrateMeshColumns(db)
}

// AddPendingDevice registers a device awaiting enrollment, keyed by a
// one-time token handed to the device owner out of band.
func (s *Store) AddPendingDevice(deviceID, token string) error {
	_, err := s.db.Exec(
		`INSERT INTO devices (device_id, enrollment_token, created_at) VALUES (?, ?, ?)`,
		deviceID, token, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// ConsumeEnrollmentToken looks up the pending device for token. It does not
// clear the token by itself — CompleteEnrollment does that once issuance
// succeeds, so a failed issuance can be retried with the same token.
func (s *Store) ConsumeEnrollmentToken(token string) (string, error) {
	var deviceID string
	err := s.db.QueryRow(
		`SELECT device_id FROM devices WHERE enrollment_token = ? AND cert_pem IS NULL`, token,
	).Scan(&deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return deviceID, nil
}

// CompleteEnrollment stores the issued certificate for deviceID and clears
// its enrollment token so it can't be reused.
func (s *Store) CompleteEnrollment(deviceID, certPEM, certSerial string) error {
	res, err := s.db.Exec(
		`UPDATE devices SET cert_pem = ?, cert_serial = ?, enrollment_token = NULL WHERE device_id = ?`,
		certPEM, certSerial, deviceID,
	)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

// GetDeviceByID returns the device record for deviceID.
func (s *Store) GetDeviceByID(deviceID string) (*Device, error) {
	var d Device
	var certPEM, certSerial sql.NullString
	var revoked int
	err := s.db.QueryRow(
		`SELECT device_id, cert_pem, cert_serial, revoked FROM devices WHERE device_id = ?`, deviceID,
	).Scan(&d.DeviceID, &certPEM, &certSerial, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.CertPEM = certPEM.String
	d.CertSerial = certSerial.String
	d.Revoked = revoked != 0
	return &d, nil
}

// RevokeDevice marks a device as revoked; cerberus-ctrl will refuse it a new
// JWT on its next login attempt.
func (s *Store) RevokeDevice(deviceID string) error {
	res, err := s.db.Exec(`UPDATE devices SET revoked = 1 WHERE device_id = ?`, deviceID)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

// AddPolicy inserts or updates (subject, resource) -> action.
func (s *Store) AddPolicy(subject, resource, action string) error {
	if action != "allow" && action != "deny" {
		return fmt.Errorf("store: invalid action %q", action)
	}
	_, err := s.db.Exec(
		`INSERT INTO policies (subject, resource, action) VALUES (?, ?, ?)
		 ON CONFLICT(subject, resource) DO UPDATE SET action = excluded.action`,
		subject, resource, action,
	)
	return err
}

// ListPolicies returns every policy rule, ready to hand to policy.NewEngine.
func (s *Store) ListPolicies() ([]policy.Rule, error) {
	rows, err := s.db.Query(`SELECT subject, resource, action FROM policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []policy.Rule
	for rows.Next() {
		var r policy.Rule
		if err := rows.Scan(&r.Subject, &r.Resource, &r.Action); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}
