package store_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/store"
)

func TestMigration_AddsMeshColumnsIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cerberus.db")

	s1, err := store.Open(path)
	require.NoError(t, err)
	require.NoError(t, s1.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, s1.CompleteEnrollment("device-a", "cert-pem", "serial-1"))
	s1.Close()

	// Reopen against the same file — migrate() runs again. Must not error
	// on "duplicate column" and must not lose the row written above.
	s2, err := store.Open(path)
	require.NoError(t, err)
	defer s2.Close()

	dev, err := s2.GetDeviceByID("device-a")
	require.NoError(t, err)
	require.Equal(t, "device-a", dev.DeviceID)

	require.NoError(t, s2.SetMeshPubkey("device-a", "pubkey-a"))
}

func TestSetMeshPubkey_UnknownDeviceFails(t *testing.T) {
	s := openTestStore(t)
	err := s.SetMeshPubkey("no-such-device", "pubkey-a")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestUpdateMeshEndpoint_UnknownDeviceFails(t *testing.T) {
	s := openTestStore(t)
	err := s.UpdateMeshEndpoint("no-such-device", "1.2.3.4:51820")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestSetMeshPubkeyThenUpdateMeshEndpoint_Roundtrip(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-1"))

	require.NoError(t, s.SetMeshPubkey("device-a", "pubkey-a"))
	require.NoError(t, s.UpdateMeshEndpoint("device-a", "1.2.3.4:51820"))
	// No direct getter yet (added in Task 4's ListMeshDevices) — this test
	// only proves both calls succeed against a real column set.
}
