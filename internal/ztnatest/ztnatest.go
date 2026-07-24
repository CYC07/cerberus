// Package ztnatest provides shared test fixtures for CA, certs, and a fake
// TCP backend, used across internal/store, internal/ctrlserver,
// internal/gwserver, and test/integration.
package ztnatest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cyc0logy/ztna/internal/ca"
)

// NewRootCA creates a fresh root CA for a single test.
func NewRootCA(t *testing.T) *ca.RootCA {
	t.Helper()
	root, err := ca.GenerateRootCA("test-root", 24*time.Hour)
	if err != nil {
		t.Fatalf("ztnatest: generate root ca: %v", err)
	}
	return root
}

// IssueDeviceCert generates a keypair and issues it a client-auth cert
// signed by root, with CommonName set to deviceID.
func IssueDeviceCert(t *testing.T, root *ca.RootCA, deviceID string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ztnatest: generate key: %v", err)
	}
	cert, err := root.IssueCert(deviceID, &key.PublicKey, time.Hour)
	if err != nil {
		t.Fatalf("ztnatest: issue cert: %v", err)
	}
	return key, cert
}

// TLSCertificate builds a tls.Certificate from an x509 cert and its key,
// suitable for tls.Config.Certificates.
func TLSCertificate(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

// EchoServer starts a TCP listener on 127.0.0.1 that echoes every
// connection's input back to it. It stops automatically when the test ends.
func EchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ztnatest: listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}
