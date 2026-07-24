package ctrlserver_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/authjwt"
	"github.com/CYC07/cerberus/internal/ca"
	"github.com/CYC07/cerberus/internal/ctrlserver"
	"github.com/CYC07/cerberus/internal/store"
	"github.com/CYC07/cerberus/internal/ztnatest"
)

func newTestServer(t *testing.T) (*ctrlserver.Server, *ca.RootCA) {
	t.Helper()
	root := ztnatest.NewRootCA(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "cerberus.db"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })

	pub, priv, err := authjwt.GenerateKey()
	require.NoError(t, err)

	return &ctrlserver.Server{
		Store:    st,
		RootCA:   root,
		Signer:   authjwt.NewSigner(priv, pub),
		CertTTL:  time.Hour,
		TokenTTL: 15 * time.Minute,
	}, root
}

func startTestHTTPS(t *testing.T, srv *ctrlserver.Server, root *ca.RootCA) *httptest.Server {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)

	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func httpsClient(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{InsecureSkipVerify: true} // test-only: server cert identity isn't under test here
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func generateCSR(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return key, string(csrPEM)
}

func generateRSACSR(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return string(csrPEM)
}

func generateInvalidCSR(t *testing.T) string {
	t.Helper()
	// Create a valid CSR then tamper with it
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	require.NoError(t, err)
	// Flip a bit to make signature invalid
	der[len(der)-1] ^= 0xff
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return string(csrPEM)
}

func TestEnroll_IssuesCertForValidToken(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	_, csrPEM := generateCSR(t)

	body, _ := json.Marshal(map[string]string{"token": "tok-123", "csr_pem": csrPEM})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.CertPEM)

	cert, err := ca.DecodeCertPEM([]byte(out.CertPEM))
	require.NoError(t, err)
	require.Equal(t, "device-a", cert.Subject.CommonName)
}

func TestEnroll_RejectsUnknownToken(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	_, csrPEM := generateCSR(t)
	body, _ := json.Marshal(map[string]string{"token": "no-such-token", "csr_pem": csrPEM})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestLogin_IssuesTokenForEnrolledDevice(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "device-a")
	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, srv.Store.CompleteEnrollment("device-a", string(ca.EncodeCertPEM(cert)), cert.SerialNumber.String()))

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/login", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.Token)

	claims, err := srv.Signer.Verify(out.Token)
	require.NoError(t, err)
	require.Equal(t, "device-a", claims.DeviceID)
	require.Equal(t, authjwt.Thumbprint(cert), claims.CertThumbprint)
}

func TestLogin_RejectsRevokedDevice(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "device-a")
	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, srv.Store.CompleteEnrollment("device-a", string(ca.EncodeCertPEM(cert)), cert.SerialNumber.String()))
	require.NoError(t, srv.Store.RevokeDevice("device-a"))

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/login", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogin_RejectsMissingClientCert(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	resp, err := httpsClient(nil).Post(ts.URL+"/login", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestPolicy_RequiresGatewayIdentity(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "device-a") // not "cerberus-gw"
	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Get(ts.URL + "/policy")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestPolicy_ReturnsRulesForGateway(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPolicy("device-a", "ssh-homepc", "allow"))

	key, cert := ztnatest.IssueDeviceCert(t, root, "cerberus-gw")
	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Get(ts.URL + "/policy")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var rules []struct {
		Subject  string `json:"Subject"`
		Resource string `json:"Resource"`
		Action   string `json:"Action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rules))
	require.Len(t, rules, 1)
	require.Equal(t, "device-a", rules[0].Subject)
}

func TestEnroll_RejectsBadJSON(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	body := []byte("not json at all")
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEnroll_RejectsMalformedCSR(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	body, _ := json.Marshal(map[string]string{"token": "tok-123", "csr_pem": "not a valid pem"})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLogin_RejectsUnknownDevice(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "unknown-device")
	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/login", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogin_RejectsStaleCertSerial(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "device-a")
	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, srv.Store.CompleteEnrollment("device-a", string(ca.EncodeCertPEM(cert)), "different-serial"))

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/login", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestEnroll_RejectsUnsupportedKeyType(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	csrPEM := generateRSACSR(t)

	body, _ := json.Marshal(map[string]string{"token": "tok-123", "csr_pem": csrPEM})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEnroll_RejectsInvalidCSRSignature(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	csrPEM := generateInvalidCSR(t)

	body, _ := json.Marshal(map[string]string{"token": "tok-123", "csr_pem": csrPEM})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
