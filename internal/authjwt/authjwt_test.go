package authjwt_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestVerify_RejectsAlgorithmNone(t *testing.T) {
	pub, _, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signer := authjwt.NewSigner(nil, pub)

	// Create a token with alg: none (unsigned) by constructing JWT manually
	// Header: {"alg":"none","typ":"JWT"}
	// Payload: {"device_id":"device-a","cert_thumbprint":"thumb",...}
	// Signature: (empty)
	tokenStr := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkZXZpY2VfaWQiOiJkZXZpY2UtYSIsImNlcnRfdGh1bWJwcmludCI6InRodW1iIn0."

	_, err = signer.Verify(tokenStr)
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
}

func TestVerify_RejectsAlgorithmConfusion(t *testing.T) {
	pub, _, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signer := authjwt.NewSigner(nil, pub)

	// Create a token signed with HS256 using the Ed25519 public key bytes as HMAC secret
	// This attempts to trick the verifier into accepting an HMAC-signed token as EdDSA
	claims := authjwt.Claims{
		DeviceID:       "device-a",
		CertThumbprint: "thumb",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign with public key bytes as HMAC secret
	tokenStr, err := token.SignedString([]byte(pub))
	require.NoError(t, err)

	_, err = signer.Verify(tokenStr)
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
}

func TestVerify_RejectsMalformedToken(t *testing.T) {
	pub, _, err := authjwt.GenerateKey()
	require.NoError(t, err)
	signer := authjwt.NewSigner(nil, pub)

	// Try to verify a clearly malformed/invalid token string
	_, err = signer.Verify("not.a.validtoken")
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)

	_, err = signer.Verify("garbage")
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)

	_, err = signer.Verify("")
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
}

func TestThumbprint_DiffersPerCert(t *testing.T) {
	root := ztnatest.NewRootCA(t)
	_, certA := ztnatest.IssueDeviceCert(t, root, "device-a")
	_, certB := ztnatest.IssueDeviceCert(t, root, "device-b")

	require.NotEqual(t, authjwt.Thumbprint(certA), authjwt.Thumbprint(certB))
}
