package store_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyc0logy/ztna/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "ztna.db"))
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnrollmentFlow(t *testing.T) {
	s := openTestStore(t)

	require.NoError(t, s.AddPendingDevice("device-a", "tok-123"))

	deviceID, err := s.ConsumeEnrollmentToken("tok-123")
	require.NoError(t, err)
	require.Equal(t, "device-a", deviceID)

	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-1"))

	dev, err := s.GetDeviceByID("device-a")
	require.NoError(t, err)
	require.Equal(t, "cert-pem", dev.CertPEM)
	require.Equal(t, "serial-1", dev.CertSerial)
	require.False(t, dev.Revoked)
}

func TestConsumeEnrollmentToken_UnknownTokenFails(t *testing.T) {
	s := openTestStore(t)
	_, err := s.ConsumeEnrollmentToken("no-such-token")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestConsumeEnrollmentToken_AlreadyEnrolledFails(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-123"))
	_, err := s.ConsumeEnrollmentToken("tok-123")
	require.NoError(t, err)
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-1"))

	_, err = s.ConsumeEnrollmentToken("tok-123")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestRevokeDevice(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, s.CompleteEnrollment("device-a", "cert-pem", "serial-1"))

	require.NoError(t, s.RevokeDevice("device-a"))

	dev, err := s.GetDeviceByID("device-a")
	require.NoError(t, err)
	require.True(t, dev.Revoked)
}

func TestRevokeDevice_UnknownDeviceFails(t *testing.T) {
	s := openTestStore(t)
	err := s.RevokeDevice("no-such-device")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestPolicyUpsertAndList(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.AddPolicy("device-a", "ssh-homepc", "allow"))
	require.NoError(t, s.AddPolicy("device-b", "ssh-homepc", "deny"))
	require.NoError(t, s.AddPolicy("device-a", "ssh-homepc", "deny")) // upsert

	rules, err := s.ListPolicies()
	require.NoError(t, err)
	require.Len(t, rules, 2)

	byDevice := map[string]string{}
	for _, r := range rules {
		byDevice[r.Subject] = r.Action
	}
	require.Equal(t, "deny", byDevice["device-a"])
	require.Equal(t, "deny", byDevice["device-b"])
}

func TestAddPolicy_RejectsInvalidAction(t *testing.T) {
	s := openTestStore(t)
	err := s.AddPolicy("device-a", "ssh-homepc", "maybe")
	require.Error(t, err)
}
