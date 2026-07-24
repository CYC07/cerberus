package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func cmdLogin(stateDir, ctrlAddr string) error {
	cert, err := loadClientCert(stateDir)
	if err != nil {
		return err
	}
	pool, err := loadCAPool(stateDir)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}}}
	resp, err := client.Post("https://"+ctrlAddr+"/login", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %s", string(b))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, "token.jwt"), []byte(out.Token), 0600)
}

func loadClientCert(stateDir string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(filepath.Join(stateDir, "device.crt"), filepath.Join(stateDir, "device.key"))
}

func loadCAPool(stateDir string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(filepath.Join(stateDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("invalid ca cert")
	}
	return pool, nil
}
