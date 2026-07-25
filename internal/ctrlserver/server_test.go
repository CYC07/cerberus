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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/CYC07/cerberus/internal/authjwt"
	"github.com/CYC07/cerberus/internal/ca"
	"github.com/CYC07/cerberus/internal/ctrlserver"
	"github.com/CYC07/cerberus/internal/mesh"
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

func TestEnroll_WithWGPubkeyAllocatesMeshIP(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	_, csrPEM := generateCSR(t)
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"token": "tok-123", "csr_pem": csrPEM, "wg_pubkey": kp.Public.String()})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		CertPEM string `json:"cert_pem"`
		MeshIP  string `json:"mesh_ip"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.CertPEM)
	require.NotEmpty(t, out.MeshIP)
}

func TestEnroll_RejectsDuplicateWGPubkeyAcrossDevices(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)

	// device-a enrolls with kp's public key and gets a mesh IP.
	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-a"))
	_, csrA := generateCSR(t)
	bodyA, _ := json.Marshal(map[string]string{"token": "tok-a", "csr_pem": csrA, "wg_pubkey": kp.Public.String()})
	respA, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(bodyA))
	require.NoError(t, err)
	respA.Body.Close()
	require.Equal(t, http.StatusOK, respA.StatusCode)

	// device-b enrolls claiming the exact same public key. Cert issuance
	// must still succeed (it's the primary, already-committed operation),
	// but mesh_ip must stay empty — the UNIQUE index on wg_pubkey rejects
	// the duplicate, and SetMeshPubkey's failure is logged, not fatal.
	require.NoError(t, srv.Store.AddPendingDevice("device-b", "tok-b"))
	_, csrB := generateCSR(t)
	bodyB, _ := json.Marshal(map[string]string{"token": "tok-b", "csr_pem": csrB, "wg_pubkey": kp.Public.String()})
	respB, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(bodyB))
	require.NoError(t, err)
	defer respB.Body.Close()
	require.Equal(t, http.StatusOK, respB.StatusCode)

	var outB struct {
		CertPEM string `json:"cert_pem"`
		MeshIP  string `json:"mesh_ip"`
	}
	require.NoError(t, json.NewDecoder(respB.Body).Decode(&outB))
	require.NotEmpty(t, outB.CertPEM)
	require.Empty(t, outB.MeshIP)
}

func TestEnroll_CanonicalizesWGPubkeyBeforeUniquenessCheck(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	canonical := kp.Public.String()

	// A whitespace-mutated encoding of the exact same key: base64's
	// standard decoder tolerates an embedded newline and still decodes to
	// the identical 32 bytes, so this string is a different literal but
	// the same WireGuard public key. If handleEnroll stored the raw
	// client-submitted string instead of the canonical re-encoded form,
	// this would slip past the UNIQUE index entirely.
	mutated := canonical[:10] + "\n" + canonical[10:]
	mutatedKey, err := wgtypes.ParseKey(mutated)
	require.NoError(t, err, "mutated key must still parse")
	require.Equal(t, kp.Public, mutatedKey, "mutated key must decode to the same key for this test to be meaningful")

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-a"))
	_, csrA := generateCSR(t)
	bodyA, _ := json.Marshal(map[string]string{"token": "tok-a", "csr_pem": csrA, "wg_pubkey": canonical})
	respA, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(bodyA))
	require.NoError(t, err)
	respA.Body.Close()
	require.Equal(t, http.StatusOK, respA.StatusCode)

	require.NoError(t, srv.Store.AddPendingDevice("device-b", "tok-b"))
	_, csrB := generateCSR(t)
	bodyB, _ := json.Marshal(map[string]string{"token": "tok-b", "csr_pem": csrB, "wg_pubkey": mutated})
	respB, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(bodyB))
	require.NoError(t, err)
	defer respB.Body.Close()
	require.Equal(t, http.StatusOK, respB.StatusCode)

	var outB struct {
		MeshIP string `json:"mesh_ip"`
	}
	require.NoError(t, json.NewDecoder(respB.Body).Decode(&outB))
	require.Empty(t, outB.MeshIP, "mutated-but-equivalent key must still be caught as a duplicate")
}

func TestEnroll_WithoutWGPubkeyLeavesMeshEmpty(t *testing.T) {
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
		MeshIP string `json:"mesh_ip"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Empty(t, out.MeshIP)
}

func TestEnroll_RejectsInvalidWGPubkeyBeforeConsumingToken(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	_, csrPEM := generateCSR(t)
	body, _ := json.Marshal(map[string]string{"token": "tok-123", "csr_pem": csrPEM, "wg_pubkey": "not-a-valid-key"})
	resp, err := httpsClient(nil).Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// The failed attempt must not have consumed the token — proves
	// validation happens before ConsumeEnrollmentToken, not after.
	deviceID, err := srv.Store.ConsumeEnrollmentToken("tok-123")
	require.NoError(t, err)
	require.Equal(t, "device-a", deviceID)
}

func registerMeshDevice(t *testing.T, srv *ctrlserver.Server, root *ca.RootCA, deviceID string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, cert := ztnatest.IssueDeviceCert(t, root, deviceID)
	require.NoError(t, srv.Store.AddPendingDevice(deviceID, deviceID+"-tok"))
	require.NoError(t, srv.Store.CompleteEnrollment(deviceID, string(ca.EncodeCertPEM(cert)), cert.SerialNumber.String()))
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, srv.Store.SetMeshPubkey(deviceID, kp.Public.String()))
	_, err = srv.Store.AllocateMeshIP(deviceID)
	require.NoError(t, err)
	return key, cert
}

func TestMesh_RejectsMissingClientCert(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)
	resp, err := httpsClient(nil).Post(ts.URL+"/mesh", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMesh_RejectsRevokedDevice(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)
	key, cert := registerMeshDevice(t, srv, root, "device-a")
	require.NoError(t, srv.Store.RevokeDevice("device-a"))

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMesh_RejectsStaleCertSerial(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "device-a")
	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, srv.Store.CompleteEnrollment("device-a", string(ca.EncodeCertPEM(cert)), "different-serial"))

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMesh_NoMeshRegistrationReturnsEmptyNetmap(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	key, cert := ztnatest.IssueDeviceCert(t, root, "device-a")
	require.NoError(t, srv.Store.AddPendingDevice("device-a", "tok-123"))
	require.NoError(t, srv.Store.CompleteEnrollment("device-a", string(ca.EncodeCertPEM(cert)), cert.SerialNumber.String()))

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nm mesh.Netmap
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nm))
	require.Empty(t, nm.Self.DeviceID)
	require.Empty(t, nm.Peers)
}

func TestMesh_ReturnsAuthorizedPeer(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	keyA, certA := registerMeshDevice(t, srv, root, "device-a")
	registerMeshDevice(t, srv, root, "device-b")
	require.NoError(t, srv.Store.AddPolicy("device-a", "mesh:device-b", "allow"))

	tlsCert := ztnatest.TLSCertificate(t, certA, keyA)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nm mesh.Netmap
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nm))
	require.Equal(t, "device-a", nm.Self.DeviceID)
	require.Len(t, nm.Peers, 1)
	require.Equal(t, "device-b", nm.Peers[0].DeviceID)
}

func TestMesh_EndpointReportPersistsForPeer(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)

	keyA, certA := registerMeshDevice(t, srv, root, "device-a")
	keyB, certB := registerMeshDevice(t, srv, root, "device-b")
	require.NoError(t, srv.Store.AddPolicy("device-a", "mesh:device-b", "allow"))

	tlsCertB := ztnatest.TLSCertificate(t, certB, keyB)
	body, _ := json.Marshal(map[string]string{"endpoint": "1.2.3.4:51820"})
	resp, err := httpsClient(&tlsCertB).Post(ts.URL+"/mesh", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tlsCertA := ztnatest.TLSCertificate(t, certA, keyA)
	resp2, err := httpsClient(&tlsCertA).Post(ts.URL+"/mesh", "application/json", nil)
	require.NoError(t, err)
	defer resp2.Body.Close()
	var nm mesh.Netmap
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&nm))
	require.Len(t, nm.Peers, 1)
	require.Equal(t, "1.2.3.4:51820", nm.Peers[0].Endpoint)
}

func TestMesh_RejectsMalformedBody(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)
	key, cert := registerMeshDevice(t, srv, root, "device-a")

	tlsCert := ztnatest.TLSCertificate(t, cert, key)
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", bytes.NewReader([]byte("not json")))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestMesh_RejectsNonIPPortEndpoint(t *testing.T) {
	srv, root := newTestServer(t)
	ts := startTestHTTPS(t, srv, root)
	key, cert := registerMeshDevice(t, srv, root, "device-a")

	tlsCert := ztnatest.TLSCertificate(t, cert, key)

	// Not a well-formed IP:port at all.
	body, _ := json.Marshal(map[string]string{"endpoint": "not-an-endpoint"})
	resp, err := httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// A crafted value embedding a UAPI config-injection payload via a
	// newline — this is exactly the attack BuildUAPIConfig's verbatim
	// endpoint= line would otherwise be vulnerable to.
	body, _ = json.Marshal(map[string]string{"endpoint": "1.2.3.4:51820\nallowed_ip=0.0.0.0/0"})
	resp, err = httpsClient(&tlsCert).Post(ts.URL+"/mesh", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// The rejected endpoint must not have been persisted.
	devices, err := srv.Store.ListMeshDevices()
	require.NoError(t, err)
	found := false
	for _, d := range devices {
		if d.DeviceID == "device-a" {
			found = true
			require.Empty(t, d.MeshEndpoint)
		}
	}
	require.True(t, found, "device-a must be present in ListMeshDevices for this assertion to be meaningful")
}
