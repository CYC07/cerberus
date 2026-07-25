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

func TestAllocateMeshIP_UnknownDeviceFails(t *testing.T) {
	s := openTestStore(t)
	_, err := s.AllocateMeshIP("no-such-device")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestAllocateMeshIP_StartsAtDotOne(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-1"))

	ip, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)
	require.Equal(t, "100.64.0.1", ip)
}

func TestAllocateMeshIP_IsIdempotent(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-1"))

	first, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)
	second, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestAllocateMeshIP_SkipsTakenAddresses(t *testing.T) {
	s := openTestStore(t)
	for _, id := range []string{"device-a", "device-b", "device-c"} {
		require.NoError(t, s.AddPendingDevice(id, id+"-tok"))
		require.NoError(t, s.CompleteEnrollment(id, "cert-pem", id+"-serial"))
	}

	a, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)
	b, err := s.AllocateMeshIP("device-b")
	require.NoError(t, err)
	c, err := s.AllocateMeshIP("device-c")
	require.NoError(t, err)

	require.Equal(t, "100.64.0.1", a)
	require.Equal(t, "100.64.0.2", b)
	require.Equal(t, "100.64.0.3", c)
}
