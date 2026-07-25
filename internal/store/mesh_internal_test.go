package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllocateMeshIP_UniqueIndexRejectsDuplicate(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cerberus.db"))
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })

	require.NoError(t, s.AddPendingDevice("device-a", "tok-a"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-a"))
	require.NoError(t, s.AddPendingDevice("device-b", "tok-b"))
	require.NoError(t, s.CompleteEnrollment("device-b", "cert-pem", "serial-b"))

	_, err = s.AllocateMeshIP("device-a")
	require.NoError(t, err)

	// Bypass AllocateMeshIP's own allocation logic entirely, via direct
	// access to the unexported db field (available here because this file
	// is package store, not package store_test) — proves the UNIQUE index
	// itself is the backstop, not just application-level care.
	_, err = s.db.Exec(`UPDATE devices SET mesh_ip = ? WHERE device_id = ?`, "100.64.0.1", "device-b")
	require.Error(t, err)
}
