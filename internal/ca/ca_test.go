package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/ca"
)

func TestIssueCert_VerifiesAgainstRoot(t *testing.T) {
	root, err := ca.GenerateRootCA("cerberus-root", 24*time.Hour)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf, err := root.IssueCert("device-a", &key.PublicKey, time.Hour)
	require.NoError(t, err)
	require.Equal(t, "device-a", leaf.Subject.CommonName)

	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)
}

func TestIssueCert_RejectsWrongRoot(t *testing.T) {
	root, err := ca.GenerateRootCA("cerberus-root", 24*time.Hour)
	require.NoError(t, err)
	otherRoot, err := ca.GenerateRootCA("other-root", 24*time.Hour)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf, err := root.IssueCert("device-a", &key.PublicKey, time.Hour)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(otherRoot.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.Error(t, err)
}

func TestEncodeDecodeCertPEM_RoundTrips(t *testing.T) {
	root, err := ca.GenerateRootCA("cerberus-root", 24*time.Hour)
	require.NoError(t, err)

	pemBytes := ca.EncodeCertPEM(root.Cert)
	decoded, err := ca.DecodeCertPEM(pemBytes)
	require.NoError(t, err)
	require.Equal(t, root.Cert.Raw, decoded.Raw)
}

func TestEncodeDecodeECKeyPEM_RoundTrips(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := ca.EncodeECKeyPEM(key)
	require.NoError(t, err)
	decoded, err := ca.DecodeECKeyPEM(pemBytes)
	require.NoError(t, err)
	require.Equal(t, key.D, decoded.D)
}

func TestIssueCert_WithIPSANs(t *testing.T) {
	root, err := ca.GenerateRootCA("cerberus-root", 24*time.Hour)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ip := net.ParseIP("127.0.0.1")
	leaf, err := root.IssueCert("gateway", &key.PublicKey, time.Hour, ip)
	require.NoError(t, err)
	require.Equal(t, "gateway", leaf.Subject.CommonName)
	require.Len(t, leaf.IPAddresses, 1)
	require.True(t, leaf.IPAddresses[0].Equal(ip))
}

func TestIssueCert_NilPublicKey(t *testing.T) {
	root, err := ca.GenerateRootCA("cerberus-root", 24*time.Hour)
	require.NoError(t, err)

	_, err = root.IssueCert("device-a", nil, time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "public key required")
}

func TestDecodeCertPEM_InvalidPEM(t *testing.T) {
	_, err := ca.DecodeCertPEM([]byte("not a valid pem"))
	require.Error(t, err)
}

func TestDecodeECKeyPEM_InvalidPEM(t *testing.T) {
	_, err := ca.DecodeECKeyPEM([]byte("not a valid pem"))
	require.Error(t, err)
}
