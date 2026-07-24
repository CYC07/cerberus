package authjwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyc0logy/ztna/internal/authjwt"
	"github.com/cyc0logy/ztna/internal/ztnatest"
)

func TestIssueAndVerify_RoundTrips(t *testing.T) {
	pub, priv, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signer := authjwt.NewSigner(priv, pub)

	root := ztnatest.NewRootCA(t)
	_, cert := ztnatest.IssueDeviceCert(t, root, "device-a")
	thumb := authjwt.Thumbprint(cert)

	token, err := signer.Issue("device-a", thumb, time.Minute)
	require.NoError(t, err)

	claims, err := signer.Verify(token)
	require.NoError(t, err)
	require.Equal(t, "device-a", claims.DeviceID)
	require.Equal(t, thumb, claims.CertThumbprint)
}

func TestVerify_RejectsExpired(t *testing.T) {
	pub, priv, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signer := authjwt.NewSigner(priv, pub)

	token, err := signer.Issue("device-a", "thumb", -time.Minute)
	require.NoError(t, err)

	_, err = signer.Verify(token)
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
}

func TestVerify_RejectsWrongSigningKey(t *testing.T) {
	pubA, privA, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signerA := authjwt.NewSigner(privA, pubA)

	pubB, _, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signerB := authjwt.NewSigner(nil, pubB)

	token, err := signerA.Issue("device-a", "thumb", time.Minute)
	require.NoError(t, err)

	_, err = signerB.Verify(token)
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
}

func TestThumbprint_DiffersPerCert(t *testing.T) {
	root := ztnatest.NewRootCA(t)
	_, certA := ztnatest.IssueDeviceCert(t, root, "device-a")
	_, certB := ztnatest.IssueDeviceCert(t, root, "device-b")

	require.NotEqual(t, authjwt.Thumbprint(certA), authjwt.Thumbprint(certB))
}
