// Mesh-related schema and methods, kept in their own file per the
// project's many-small-files convention. Mesh IP allocation lives here
// rather than in internal/mesh because uniqueness is a store-owned
// invariant, and internal/mesh already imports internal/store for
// MeshDevice — the reverse import would cycle.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
)

// MeshDevice is a device's WireGuard mesh membership record: identity plus
// mesh IP, present only for devices that submitted a wg_pubkey at enroll
// time. ListMeshDevices (Task 4) includes revoked devices — callers decide
// whether to exclude them, so that decision stays visible at the call
// site instead of being buried in a query.
type MeshDevice struct {
	DeviceID     string
	WGPubkey     string
	MeshIP       string
	MeshEndpoint string // "" if the device hasn't reported one yet
	Revoked      bool
}

var meshPrefix = netip.MustParsePrefix("100.64.0.0/10")

func migrateMeshColumns(db *sql.DB) error {
	cols, err := devicesTableColumns(db)
	if err != nil {
		return err
	}
	for _, c := range []struct{ name, ddl string }{
		{"wg_pubkey", "ALTER TABLE devices ADD COLUMN wg_pubkey TEXT"},
		{"mesh_ip", "ALTER TABLE devices ADD COLUMN mesh_ip TEXT"},
		{"mesh_endpoint", "ALTER TABLE devices ADD COLUMN mesh_endpoint TEXT"},
	} {
		if cols[c.name] {
			continue
		}
		if _, err := db.Exec(c.ddl); err != nil {
			return fmt.Errorf("store: migrate %s: %w", c.name, err)
		}
	}
	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mesh_ip ON devices(mesh_ip) WHERE mesh_ip IS NOT NULL`)
	return err
}

func devicesTableColumns(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(devices)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// SetMeshPubkey stores deviceID's WireGuard public key. It does not
// allocate a mesh IP — call AllocateMeshIP separately for that.
func (s *Store) SetMeshPubkey(deviceID, wgPubkey string) error {
	res, err := s.db.Exec(`UPDATE devices SET wg_pubkey = ? WHERE device_id = ?`, wgPubkey, deviceID)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

// UpdateMeshEndpoint records deviceID's last-reported WireGuard UDP listen
// address, so peers know where to dial it.
func (s *Store) UpdateMeshEndpoint(deviceID, endpoint string) error {
	res, err := s.db.Exec(`UPDATE devices SET mesh_endpoint = ? WHERE device_id = ?`, endpoint, deviceID)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

func checkAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AllocateMeshIP returns deviceID's persistent mesh IP, allocating one if
// it doesn't already have one. Idempotent: a second call for the same
// device returns the same IP rather than allocating a new one. Allocation
// picks the lowest unused host address in 100.64.0.0/10 (CGNAT range,
// Tailscale convention), starting at 100.64.0.1 — 100.64.0.0 is the
// network address and is never allocated.
func (s *Store) AllocateMeshIP(deviceID string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var existing sql.NullString
	err = tx.QueryRow(`SELECT mesh_ip FROM devices WHERE device_id = ?`, deviceID).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if existing.Valid && existing.String != "" {
		return existing.String, nil
	}

	rows, err := tx.Query(`SELECT mesh_ip FROM devices WHERE mesh_ip IS NOT NULL`)
	if err != nil {
		return "", err
	}
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			rows.Close()
			return "", err
		}
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			used[addr] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	next, err := nextFreeMeshIP(used)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE devices SET mesh_ip = ? WHERE device_id = ?`, next, deviceID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return next, nil
}

// nextFreeMeshIP picks the lowest address in meshPrefix not present in
// used.
func nextFreeMeshIP(used map[netip.Addr]bool) (string, error) {
	base := meshPrefix.Addr().As4()
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	const hostBits = 32 - 10 // /10 prefix
	const maxHosts = 1 << hostBits
	for offset := uint32(1); offset < maxHosts; offset++ {
		n := start + offset
		addr := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
		if !used[addr] {
			return addr.String(), nil
		}
	}
	return "", errors.New("store: mesh IP pool exhausted")
}
