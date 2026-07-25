// Package ctrlserver implements cerberus-ctrl's HTTP handlers: device
// enrollment (CSR signing), login (cert -> JWT), and policy distribution
// to cerberus-gw.
package ctrlserver

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/CYC07/cerberus/internal/authjwt"
	"github.com/CYC07/cerberus/internal/ca"
	"github.com/CYC07/cerberus/internal/mesh"
	"github.com/CYC07/cerberus/internal/policy"
	"github.com/CYC07/cerberus/internal/store"
)

// Server holds cerberus-ctrl's dependencies for its HTTP handlers.
type Server struct {
	Store    *store.Store
	RootCA   *ca.RootCA
	Signer   *authjwt.Signer
	CertTTL  time.Duration
	TokenTTL time.Duration
}

// Handler returns the routed HTTP handler for /enroll, /login, /policy, /mesh.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/policy", s.handlePolicy)
	mux.HandleFunc("/mesh", s.handleMesh)
	return mux
}

// handleEnroll signs a CSR for a device that presents a valid, unused
// enrollment token. The device's identity (deviceID) comes from the token
// lookup, never from the CSR's own subject field, so a client can't
// self-assert an identity it wasn't issued.
//
// An optional wg_pubkey registers the device for the WireGuard mesh in
// the same call — validated before the enrollment token is consumed or
// any store state changes, because ConsumeEnrollmentToken requires
// cert_pem IS NULL and can't be retried once CompleteEnrollment has run;
// a malformed key must fail without burning the one-time token. Once the
// cert is issued (the primary, already-committed operation), a mesh IP
// allocation failure does not fail the whole enroll — it's logged
// server-side and the response simply omits mesh_ip.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		CSR      string `json:"csr_pem"`
		WGPubkey string `json:"wg_pubkey,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.WGPubkey != "" {
		if _, err := wgtypes.ParseKey(req.WGPubkey); err != nil {
			http.Error(w, "invalid wg_pubkey", http.StatusBadRequest)
			return
		}
	}
	deviceID, err := s.Store.ConsumeEnrollmentToken(req.Token)
	if err != nil {
		http.Error(w, "enrollment denied", http.StatusForbidden)
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "unsupported key type", http.StatusBadRequest)
		return
	}
	cert, err := s.RootCA.IssueCert(deviceID, pub, s.CertTTL)
	if err != nil {
		http.Error(w, "issuance failed", http.StatusInternalServerError)
		return
	}
	certPEM := ca.EncodeCertPEM(cert)
	if err := s.Store.CompleteEnrollment(deviceID, string(certPEM), cert.SerialNumber.String()); err != nil {
		http.Error(w, "enrollment failed", http.StatusInternalServerError)
		return
	}

	var meshIP string
	if req.WGPubkey != "" {
		if err := s.Store.SetMeshPubkey(deviceID, req.WGPubkey); err != nil {
			log.Printf("enroll %s: set mesh pubkey: %v", deviceID, err)
		} else if ip, err := s.Store.AllocateMeshIP(deviceID); err != nil {
			log.Printf("enroll %s: allocate mesh ip: %v", deviceID, err)
		} else {
			meshIP = ip
		}
	}

	json.NewEncoder(w).Encode(struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
		MeshIP  string `json:"mesh_ip,omitempty"`
	}{
		CertPEM: string(certPEM),
		CAPEM:   string(ca.EncodeCertPEM(s.RootCA.Cert)),
		MeshIP:  meshIP,
	})
}

// handleLogin issues a fresh cert-bound JWT to a device presenting a valid,
// non-revoked client cert whose serial matches what we issued it.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	peer := r.TLS.PeerCertificates[0]
	deviceID := peer.Subject.CommonName
	dev, err := s.Store.GetDeviceByID(deviceID)
	if err != nil || dev.Revoked || dev.CertSerial != peer.SerialNumber.String() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := s.Signer.Issue(deviceID, authjwt.Thumbprint(peer), s.TokenTTL)
	if err != nil {
		http.Error(w, "token issuance failed", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
	}{Token: token})
}

// handlePolicy serves the full policy rule set to cerberus-gw only, identified
// by its client cert's CommonName.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "cerberus-gw" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rules, err := s.Store.ListPolicies()
	if err != nil {
		http.Error(w, "policy fetch failed", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(rules)
}

// handleMesh serves a device's WireGuard mesh netmap: its own mesh
// identity plus the peer set it's authorized to reach. Authentication
// mirrors handleLogin exactly (cert present, device known, not revoked,
// cert serial matches what ctrl issued) — unlike /policy, which is gated
// to the single cerberus-gw identity, /mesh must accept every enrolled,
// non-revoked device, so it can't reuse handlePolicy's weaker check.
// ctrl's HTTPS server runs ClientAuth: tls.VerifyClientCertIfGiven (not
// RequireAndVerifyClientCert), so a certless client still completes the
// TLS handshake and reaches this handler — the cert-present check below
// is load-bearing, not decorative.
//
// The request body optionally carries {"endpoint":"host:port"}: the
// device's own last-known WireGuard UDP listen address. ctrl persists it
// and hands it to peers — WireGuard's own endpoint roaming only ever
// discovers a peer's address from an already-authenticated inbound
// packet, so at least one side of a communicating pair must self-report
// an endpoint this way or neither side can send the first handshake.
func (s *Server) handleMesh(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	peer := r.TLS.PeerCertificates[0]
	deviceID := peer.Subject.CommonName
	dev, err := s.Store.GetDeviceByID(deviceID)
	if err != nil || dev.Revoked || dev.CertSerial != peer.SerialNumber.String() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Endpoint != "" {
		if err := s.Store.UpdateMeshEndpoint(deviceID, req.Endpoint); err != nil {
			http.Error(w, "endpoint update failed", http.StatusInternalServerError)
			return
		}
	}

	devices, err := s.Store.ListMeshDevices()
	if err != nil {
		http.Error(w, "mesh fetch failed", http.StatusInternalServerError)
		return
	}
	rules, err := s.Store.ListPolicies()
	if err != nil {
		http.Error(w, "policy fetch failed", http.StatusInternalServerError)
		return
	}
	nm := mesh.BuildNetmap(deviceID, devices, policy.NewEngine(rules))
	json.NewEncoder(w).Encode(nm)
}
