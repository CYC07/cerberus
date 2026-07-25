// Package store: mesh-related schema and methods, kept in their own file
// per the project's many-small-files convention. Mesh IP allocation lives
// here rather than in internal/mesh because uniqueness is a store-owned
// invariant, and internal/mesh already imports internal/store for
// MeshDevice — the reverse import would cycle.
package store

import (
	"database/sql"
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
