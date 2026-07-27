package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/CYC07/cerberus/internal/mesh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	meshIfaceName  = "cerberus0"
	meshListenPort = 51820
)

// cmdMeshUp brings up the local WireGuard mesh interface: loads the
// private key persisted by cmdEnroll, fetches this device's own mesh IP
// and authorized peer set from cerberus-ctrl, creates the kernel TUN
// interface (requires root / CAP_NET_ADMIN), assigns the mesh address,
// applies the initial peer set, then polls /mesh every 30s and
// re-applies on change — exact structural mirror of
// cmd/cerberus-gw/main.go's pollPolicy/fetchPolicy.
//
// advertiseEndpoint, if non-empty, is reported to ctrl on the first call
// only, so peers learn where to dial this device. At least one side of
// any communicating pair needs to report one — WireGuard can only learn
// a peer's address from a packet it already received, never bootstrap a
// connection to an address nobody reported (see the design spec's
// endpoint invariant).
func cmdMeshUp(stateDir, ctrlAddr, advertiseEndpoint string) error {
	privKeyBytes, err := os.ReadFile(filepath.Join(stateDir, "mesh.key"))
	if err != nil {
		return fmt.Errorf("read mesh key (run 'cerberusctl enroll' first): %w", err)
	}
	privKey, err := wgtypes.ParseKey(string(privKeyBytes))
	if err != nil {
		return fmt.Errorf("parse mesh key: %w", err)
	}

	cert, err := loadClientCert(stateDir)
	if err != nil {
		return err
	}
	pool, err := loadCAPool(stateDir)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		}},
	}

	nm, err := fetchNetmap(client, ctrlAddr, advertiseEndpoint)
	if err != nil {
		return fmt.Errorf("initial mesh fetch: %w", err)
	}
	if nm.Self.MeshIP == "" {
		return fmt.Errorf("device has no mesh registration; re-run 'cerberusctl enroll'")
	}

	dev, err := mesh.Up(meshIfaceName, privKey, meshListenPort)
	if err != nil {
		return fmt.Errorf("bring up mesh interface: %w", err)
	}
	defer dev.Close()

	if err := dev.AssignAddress(nm.Self.MeshIP + "/32"); err != nil {
		return fmt.Errorf("assign mesh address: %w", err)
	}
	if err := dev.ApplyNetmap(privKey, meshListenPort, nm.Peers); err != nil {
		return fmt.Errorf("apply initial netmap: %w", err)
	}
	fmt.Printf("mesh up: %s = %s, %d peer(s)\n", meshIfaceName, nm.Self.MeshIP, len(nm.Peers))
	lastPeers := nm.Peers

	for {
		time.Sleep(30 * time.Second)
		next, err := fetchNetmap(client, ctrlAddr, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "mesh poll:", err)
			continue
		}
		// Skip the IpcSet entirely when the peer set hasn't changed —
		// BuildUAPIConfig's replace_peers=true tears down and rehandshakes
		// every peer on each call, so applying an unchanged netmap every
		// 30s forever would cause a periodic connectivity blip on an
		// otherwise-idle mesh for no reason.
		if slices.Equal(next.Peers, lastPeers) {
			continue
		}
		if err := dev.ApplyNetmap(privKey, meshListenPort, next.Peers); err != nil {
			fmt.Fprintln(os.Stderr, "mesh apply:", err)
			continue
		}
		lastPeers = next.Peers
	}
}

func fetchNetmap(client *http.Client, ctrlAddr, endpoint string) (*mesh.Netmap, error) {
	var body io.Reader
	if endpoint != "" {
		b, err := json.Marshal(struct {
			Endpoint string `json:"endpoint"`
		}{Endpoint: endpoint})
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	resp, err := client.Post("https://"+ctrlAddr+"/mesh", "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("mesh fetch: %s", string(b))
	}
	var nm mesh.Netmap
	if err := json.NewDecoder(resp.Body).Decode(&nm); err != nil {
		return nil, err
	}
	return &nm, nil
}
