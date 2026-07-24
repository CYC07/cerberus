// Package ctrlserver implements ztna-ctrl's HTTP handlers: device
// enrollment (CSR signing), login (cert -> JWT), and policy distribution
// to ztna-gw.
package ctrlserver

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/cyc0logy/ztna/internal/authjwt"
	"github.com/cyc0logy/ztna/internal/ca"
	"github.com/cyc0logy/ztna/internal/store"
)

// Server holds ztna-ctrl's dependencies for its HTTP handlers.
type Server struct {
	Store    *store.Store
	RootCA   *ca.RootCA
	Signer   *authjwt.Signer
	CertTTL  time.Duration
	TokenTTL time.Duration
}

// Handler returns the routed HTTP handler for /enroll, /login, /policy.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/policy", s.handlePolicy)
	return mux
}

// handleEnroll signs a CSR for a device that presents a valid, unused
// enrollment token. The device's identity (deviceID) comes from the token
// lookup, never from the CSR's own subject field, so a client can't
// self-assert an identity it wasn't issued.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		CSR   string `json:"csr_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
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
	json.NewEncoder(w).Encode(struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}{
		CertPEM: string(certPEM),
		CAPEM:   string(ca.EncodeCertPEM(s.RootCA.Cert)),
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

// handlePolicy serves the full policy rule set to ztna-gw only, identified
// by its client cert's CommonName.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "ztna-gw" {
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
