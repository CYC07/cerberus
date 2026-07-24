package authjwt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer issues and verifies cert-bound JWTs using Ed25519 (EdDSA).
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSigner wraps a keypair. priv may be nil for a verify-only Signer
// (used by cerberus-gw, which only ever verifies tokens issued by cerberus-ctrl).
func NewSigner(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Signer {
	return &Signer{priv: priv, pub: pub}
}

// GenerateKey creates a new Ed25519 signing keypair for cerberus-ctrl.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// Claims are the cert-bound session token claims. CertThumbprint must match
// the SHA-256 thumbprint of the client certificate presenting this token —
// verified by the caller (cerberus-gw), not by Verify itself, since Verify has
// no access to the connection's peer certificate.
type Claims struct {
	DeviceID       string `json:"device_id"`
	CertThumbprint string `json:"cert_thumbprint"`
	jwt.RegisteredClaims
}

// Thumbprint returns the hex-encoded SHA-256 hash of the certificate's DER
// bytes, used to bind a JWT to the specific certificate that requested it.
func Thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Issue creates a signed, short-lived token bound to certThumbprint.
func (s *Signer) Issue(deviceID, certThumbprint string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		DeviceID:       deviceID,
		CertThumbprint: certThumbprint,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(s.priv)
}

// ErrInvalidToken is returned for any verification failure (bad signature,
// wrong algorithm, expired, malformed) without distinguishing which, so
// callers can't use error messages to enumerate why a token was rejected.
var ErrInvalidToken = errors.New("authjwt: invalid token")

// Verify checks the token's signature and expiry and returns its claims.
func (s *Signer) Verify(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, ErrInvalidToken
		}
		return s.pub, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
