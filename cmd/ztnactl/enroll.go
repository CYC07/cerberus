package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cyc0logy/ztna/internal/ca"
)

func cmdEnroll(stateDir, ctrlAddr, caCertPath, token string) error {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return errors.New("invalid ca cert")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	body, err := json.Marshal(struct {
		Token string `json:"token"`
		CSR   string `json:"csr_pem"`
	}{Token: token, CSR: string(csrPEM)})
	if err != nil {
		return err
	}
	resp, err := client.Post("https://"+ctrlAddr+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enroll failed: %s", string(b))
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}

	keyPEM, err := ca.EncodeECKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stateDir, "device.key"), keyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stateDir, "device.crt"), []byte(out.CertPEM), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, "ca.crt"), []byte(out.CAPEM), 0644)
}
