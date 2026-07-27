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

func TestSetMeshPubkey_RejectsDuplicateAcrossDevices(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-a"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-a"))
	require.NoError(t, s.AddPendingDevice("device-b", "tok-b"))
	require.NoError(t, s.CompleteEnrollment("device-b", "cert-pem", "serial-b"))

	require.NoError(t, s.SetMeshPubkey("device-a", "same-pubkey"))
	// A second device claiming the exact same key must be rejected by the
	// UNIQUE index — pubkeys aren't secret, so nothing else stops one
	// enrolled device from claiming another's identity.
	err := s.SetMeshPubkey("device-b", "same-pubkey")
	require.Error(t, err)
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

func TestListMeshDevices_ExcludesIncompleteRegistration(t *testing.T) {
	s := openTestStore(t)
	// device-a: full mesh registration
	require.NoError(t, s.AddPendingDevice("device-a", "tok-a"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-a"))
	require.NoError(t, s.SetMeshPubkey("device-a", "pubkey-a"))
	_, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)

	// device-b: enrolled, no wg_pubkey at all
	require.NoError(t, s.AddPendingDevice("device-b", "tok-b"))
	require.NoError(t, s.CompleteEnrollment("device-b", "cert-pem", "serial-b"))

	// device-c: has a pubkey but never got a mesh IP allocated
	require.NoError(t, s.AddPendingDevice("device-c", "tok-c"))
	require.NoError(t, s.CompleteEnrollment("device-c", "cert-pem", "serial-c"))
	require.NoError(t, s.SetMeshPubkey("device-c", "pubkey-c"))

	devices, err := s.ListMeshDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.Equal(t, "device-a", devices[0].DeviceID)
	require.Equal(t, "pubkey-a", devices[0].WGPubkey)
	require.Equal(t, "100.64.0.1", devices[0].MeshIP)
	require.Empty(t, devices[0].MeshEndpoint)
	require.False(t, devices[0].Revoked)
}

func TestListMeshDevices_IncludesRevokedDevices(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-a"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-a"))
	require.NoError(t, s.SetMeshPubkey("device-a", "pubkey-a"))
	_, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)
	require.NoError(t, s.RevokeDevice("device-a"))

	devices, err := s.ListMeshDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.True(t, devices[0].Revoked)
}

func TestListMeshDevices_ReflectsReportedEndpoint(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-a"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-a"))
	require.NoError(t, s.SetMeshPubkey("device-a", "pubkey-a"))
	_, err := s.AllocateMeshIP("device-a")
	require.NoError(t, err)
	require.NoError(t, s.UpdateMeshEndpoint("device-a", "1.2.3.4:51820"))

	devices, err := s.ListMeshDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.Equal(t, "1.2.3.4:51820", devices[0].MeshEndpoint)
}

func TestListMeshDevices_OrderedByDeviceID(t *testing.T) {
	s := openTestStore(t)
	// Registered out of alphabetical device_id order, AND with wg_pubkey
	// values that sort in yet another, unrelated order (zeta -> "mmm",
	// alpha -> "zzz", mid -> "aaa") — deliberately decorrelated from
	// device_id so this test can't pass by accident if the query happens
	// to scan via the wg_pubkey index (sorted by pubkey) or insertion
	// order instead of genuinely ordering by device_id. Only an actual
	// "ORDER BY device_id" produces alpha, mid, zeta here.
	devices := []struct{ id, pubkey string }{
		{"zeta", "mmm-pubkey"},
		{"alpha", "zzz-pubkey"},
		{"mid", "aaa-pubkey"},
	}
	for _, d := range devices {
		require.NoError(t, s.AddPendingDevice(d.id, d.id+"-tok"))
		require.NoError(t, s.CompleteEnrollment(d.id, "cert-pem", d.id+"-serial"))
		require.NoError(t, s.SetMeshPubkey(d.id, d.pubkey))
		_, err := s.AllocateMeshIP(d.id)
		require.NoError(t, err)
	}

	got, err := s.ListMeshDevices()
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, []string{"alpha", "mid", "zeta"}, []string{got[0].DeviceID, got[1].DeviceID, got[2].DeviceID})
}
