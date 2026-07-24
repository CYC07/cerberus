package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CYC07/cerberus/internal/authjwt"
	"github.com/CYC07/cerberus/internal/ca"
	"github.com/CYC07/cerberus/internal/ctrlserver"
	"github.com/CYC07/cerberus/internal/store"
)

const (
	stateDir = "./ctrl-state"
	certTTL  = 365 * 24 * time.Hour
	tokenTTL = 15 * time.Minute
)

func main() {
	if len(os.Args) < 2 {
		fatalUsage()
	}
	switch os.Args[1] {
	case "serve":
		runServe()
	case "admin":
		runAdmin(os.Args[2:])
	default:
		fatalUsage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  cerberus-ctrl serve
  cerberus-ctrl admin device add <device_id>
  cerberus-ctrl admin device revoke <device_id>
  cerberus-ctrl admin policy add <subject> <resource> <allow|deny>
  cerberus-ctrl admin gw-cert <output_dir> <gateway_ip>`)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func fatalUsage() {
	usage()
	os.Exit(1)
}

func openStore() *store.Store {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		fatalf("state dir: %v", err)
	}
	st, err := store.Open(filepath.Join(stateDir, "cerberus.db"))
	if err != nil {
		fatalf("open store: %v", err)
	}
	return st
}

func loadOrCreateRootCA() *ca.RootCA {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		fatalf("state dir: %v", err)
	}
	certPath := filepath.Join(stateDir, "root-ca.crt")
	keyPath := filepath.Join(stateDir, "root-ca.key")
	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			fatalf("read root ca key: %v", err)
		}
		cert, err := ca.DecodeCertPEM(certPEM)
		if err != nil {
			fatalf("decode root ca cert: %v", err)
		}
		key, err := ca.DecodeECKeyPEM(keyPEM)
		if err != nil {
			fatalf("decode root ca key: %v", err)
		}
		return &ca.RootCA{Cert: cert, Key: key}
	}
	root, err := ca.GenerateRootCA("cerberus-root", 10*365*24*time.Hour)
	if err != nil {
		fatalf("generate root ca: %v", err)
	}
	if err := os.WriteFile(certPath, ca.EncodeCertPEM(root.Cert), 0644); err != nil {
		fatalf("write root ca cert: %v", err)
	}
	keyPEM, err := ca.EncodeECKeyPEM(root.Key)
	if err != nil {
		fatalf("encode root ca key: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		fatalf("write root ca key: %v", err)
	}
	return root
}

func loadOrCreateSigner() *authjwt.Signer {
	pubPath := filepath.Join(stateDir, "jwt.pub")
	privPath := filepath.Join(stateDir, "jwt.key")
	if pubHex, err := os.ReadFile(pubPath); err == nil {
		privHex, err := os.ReadFile(privPath)
		if err != nil {
			fatalf("read jwt key: %v", err)
		}
		pub, err := hex.DecodeString(string(pubHex))
		if err != nil {
			fatalf("decode jwt pubkey: %v", err)
		}
		priv, err := hex.DecodeString(string(privHex))
		if err != nil {
			fatalf("decode jwt privkey: %v", err)
		}
		return authjwt.NewSigner(priv, pub)
	}
	pub, priv, err := authjwt.GenerateKey()
	if err != nil {
		fatalf("generate jwt key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
		fatalf("write jwt pubkey: %v", err)
	}
	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)), 0600); err != nil {
		fatalf("write jwt privkey: %v", err)
	}
	return authjwt.NewSigner(priv, pub)
}

// loadOrIssueServerCert issues ctrl's own TLS server cert, self-signed by
// its root CA, the first time serve runs, with a loopback IP SAN so a
// gateway/client dialing 127.0.0.1 can verify it without skipping checks.
func loadOrIssueServerCert(root *ca.RootCA) tls.Certificate {
	certPath := filepath.Join(stateDir, "server.crt")
	keyPath := filepath.Join(stateDir, "server.key")
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			fatalf("load server cert: %v", err)
		}
		return cert
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatalf("generate server key: %v", err)
	}
	cert, err := root.IssueCert("cerberus-ctrl", &key.PublicKey, certTTL, net.ParseIP("127.0.0.1"))
	if err != nil {
		fatalf("issue server cert: %v", err)
	}
	certPEM := ca.EncodeCertPEM(cert)
	keyPEM, err := ca.EncodeECKeyPEM(key)
	if err != nil {
		fatalf("encode server key: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		fatalf("write server cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		fatalf("write server key: %v", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fatalf("load issued server cert: %v", err)
	}
	return tlsCert
}

func runServe() {
	st := openStore()
	defer st.Close()
	root := loadOrCreateRootCA()
	signer := loadOrCreateSigner()
	serverCert := loadOrIssueServerCert(root)

	srv := &ctrlserver.Server{
		Store:    st,
		RootCA:   root,
		Signer:   signer,
		CertTTL:  certTTL,
		TokenTTL: tokenTTL,
	}

	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)

	httpSrv := &http.Server{
		Addr:    ":8443",
		Handler: srv.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS13,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	fmt.Println("cerberus-ctrl listening on :8443")
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
		fatalf("serve: %v", err)
	}
}

func runAdmin(args []string) {
	if len(args) < 1 {
		fatalUsage()
	}
	switch args[0] {
	case "device":
		st := openStore()
		defer st.Close()
		runAdminDevice(st, args[1:])
	case "policy":
		st := openStore()
		defer st.Close()
		runAdminPolicy(st, args[1:])
	case "gw-cert":
		root := loadOrCreateRootCA()
		runAdminGWCert(root, args[1:])
	default:
		fatalUsage()
	}
}

func runAdminDevice(st *store.Store, args []string) {
	if len(args) < 2 {
		fatalUsage()
	}
	switch args[0] {
	case "add":
		deviceID := args[1]
		token := randomToken()
		if err := st.AddPendingDevice(deviceID, token); err != nil {
			fatalf("add device: %v", err)
		}
		fmt.Printf("device %q registered. enrollment token: %s\n", deviceID, token)
	case "revoke":
		deviceID := args[1]
		if err := st.RevokeDevice(deviceID); err != nil {
			fatalf("revoke device: %v", err)
		}
		fmt.Printf("device %q revoked\n", deviceID)
	default:
		fatalUsage()
	}
}

func runAdminPolicy(st *store.Store, args []string) {
	if len(args) != 4 || args[0] != "add" {
		fatalUsage()
	}
	subject, resource, action := args[1], args[2], args[3]
	if err := st.AddPolicy(subject, resource, action); err != nil {
		fatalf("add policy: %v", err)
	}
	fmt.Printf("policy added: %s -> %s: %s\n", subject, resource, action)
}

func runAdminGWCert(root *ca.RootCA, args []string) {
	if len(args) != 2 {
		fatalUsage()
	}
	outDir, ipStr := args[0], args[1]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fatalf("invalid ip: %s", ipStr)
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		fatalf("mkdir: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}
	cert, err := root.IssueCert("cerberus-gw", &key.PublicKey, certTTL, ip)
	if err != nil {
		fatalf("issue cert: %v", err)
	}
	certPEM := ca.EncodeCertPEM(cert)
	keyPEM, err := ca.EncodeECKeyPEM(key)
	if err != nil {
		fatalf("encode key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "gw.crt"), certPEM, 0644); err != nil {
		fatalf("write gw cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "gw.key"), keyPEM, 0600); err != nil {
		fatalf("write gw key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "ca.crt"), ca.EncodeCertPEM(root.Cert), 0644); err != nil {
		fatalf("write ca cert: %v", err)
	}

	// Ensure the JWT signing keypair exists (it's otherwise created lazily
	// by `serve` on first run) and bundle its public key alongside the
	// gateway's cert/key/CA so the output directory is self-contained and
	// ready to copy to the gateway host, even if `serve` has never run.
	loadOrCreateSigner()
	jwtPub, err := os.ReadFile(filepath.Join(stateDir, "jwt.pub"))
	if err != nil {
		fatalf("read jwt pubkey: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "jwt.pub"), jwtPub, 0644); err != nil {
		fatalf("write jwt pubkey: %v", err)
	}

	fmt.Println("gw cert bundle written to", outDir)
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		fatalf("random token: %v", err)
	}
	return hex.EncodeToString(b)
}
