package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

// RootCA holds the CA's signing key and self-signed certificate.
type RootCA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// GenerateRootCA creates a new self-signed ECDSA P-256 root CA.
func GenerateRootCA(commonName string, validFor time.Duration) (*RootCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &RootCA{Cert: cert, Key: key}, nil
}

// IssueCert signs a leaf certificate for deviceID, binding pub as its public
// key. ipSANs is optional and used only for server certs (ctrl, gw) that
// need to satisfy hostname verification when dialed by IP.
func (ca *RootCA) IssueCert(deviceID string, pub *ecdsa.PublicKey, validFor time.Duration, ipSANs ...net.IP) (*x509.Certificate, error) {
	if pub == nil {
		return nil, errors.New("ca: public key required")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipSANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// EncodeCertPEM encodes a certificate as PEM for storage/transport.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// EncodeECKeyPEM encodes an ECDSA private key as PEM for storage.
func EncodeECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// DecodeCertPEM parses a PEM-encoded certificate.
func DecodeCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ca: invalid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// DecodeECKeyPEM parses a PEM-encoded ECDSA private key.
func DecodeECKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ca: invalid PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
