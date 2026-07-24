package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cyc0logy/ztna/internal/authjwt"
	"github.com/cyc0logy/ztna/internal/gwserver"
	"github.com/cyc0logy/ztna/internal/policy"
)

// config is a JSON file, e.g.:
//
//	{
//	  "listen_addr": "0.0.0.0:9443",
//	  "ctrl_addr": "127.0.0.1:8443",
//	  "ca_cert_path": "./gw-state/ca.crt",
//	  "cert_path": "./gw-state/gw.crt",
//	  "key_path": "./gw-state/gw.key",
//	  "jwt_pub_path": "./gw-state/jwt.pub",
//	  "backends": {"ssh-homepc": "127.0.0.1:22"}
//	}
type config struct {
	ListenAddr string            `json:"listen_addr"`
	CtrlAddr   string            `json:"ctrl_addr"`
	CACertPath string            `json:"ca_cert_path"`
	CertPath   string            `json:"cert_path"`
	KeyPath    string            `json:"key_path"`
	JWTPubPath string            `json:"jwt_pub_path"`
	Backends   map[string]string `json:"backends"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: ztna-gw <config.json>")
		os.Exit(1)
	}
	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		fatalf("config: %v", err)
	}

	caPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		fatalf("read ca cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fatalf("invalid ca cert")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		fatalf("load gw cert: %v", err)
	}

	pubHex, err := os.ReadFile(cfg.JWTPubPath)
	if err != nil {
		fatalf("read jwt pubkey: %v", err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil {
		fatalf("decode jwt pubkey: %v", err)
	}
	signer := authjwt.NewSigner(nil, pub) // gw only verifies, never signs

	g := gwserver.New(signer, cfg.Backends)
	go pollPolicy(g, cfg, serverCert, pool)

	ln, err := gwserver.TLSListener(cfg.ListenAddr, serverCert, pool)
	if err != nil {
		fatalf("listen: %v", err)
	}
	fmt.Println("ztna-gw listening on", cfg.ListenAddr)
	if err := gwserver.Serve(ln, g); err != nil {
		fatalf("serve: %v", err)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func pollPolicy(g *gwserver.Gateway, cfg *config, cert tls.Certificate, pool *x509.CertPool) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			},
		},
	}
	for {
		rules, err := fetchPolicy(client, cfg.CtrlAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "policy poll:", err)
		} else {
			g.SetPolicy(policy.NewEngine(rules))
		}
		time.Sleep(30 * time.Second)
	}
}

func fetchPolicy(client *http.Client, ctrlAddr string) ([]policy.Rule, error) {
	resp, err := client.Get("https://" + ctrlAddr + "/policy")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("policy fetch: %s", string(b))
	}
	var rules []policy.Rule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		return nil, err
	}
	return rules, nil
}
