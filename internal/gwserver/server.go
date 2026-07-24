// Package gwserver implements ztna-gw's connection handling: mTLS peer
// identity, JWT verification bound to that identity, policy enforcement,
// and proxying to the resource's backend.
package gwserver

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"sync/atomic"

	"github.com/cyc0logy/ztna/internal/authjwt"
	"github.com/cyc0logy/ztna/internal/gwproxy"
	"github.com/cyc0logy/ztna/internal/policy"
	"github.com/cyc0logy/ztna/internal/proto"
)

// Gateway holds the data plane's dependencies and mutable policy state.
type Gateway struct {
	Signer   *authjwt.Signer
	Backends map[string]string // resource name -> backend address
	policy   atomic.Value      // holds *policy.Engine
}

// New creates a Gateway with an empty (deny-all) policy; call SetPolicy
// once real rules are available.
func New(signer *authjwt.Signer, backends map[string]string) *Gateway {
	g := &Gateway{Signer: signer, Backends: backends}
	g.SetPolicy(policy.NewEngine(nil))
	return g
}

// SetPolicy atomically replaces the active policy engine.
func (g *Gateway) SetPolicy(e *policy.Engine) {
	g.policy.Store(e)
}

func (g *Gateway) currentPolicy() *policy.Engine {
	return g.policy.Load().(*policy.Engine)
}

// HandleConn processes one already-accepted TLS connection end to end:
// completes the handshake, reads the client's resource+JWT request,
// verifies the JWT is valid and bound to the connecting certificate,
// checks policy, and either proxies to the backend or denies. All deny
// paths write a single generic status byte and log the specific reason
// server-side only.
func (g *Gateway) HandleConn(conn *tls.Conn) {
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		log.Printf("gw: deny (handshake): %v", err)
		return
	}
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		log.Printf("gw: deny (no client cert)")
		return
	}
	peer := peers[0]

	req, err := proto.ReadConnectRequest(conn)
	if err != nil {
		log.Printf("gw: deny (bad request) device=%s: %v", peer.Subject.CommonName, err)
		return
	}

	claims, err := g.Signer.Verify(req.JWT)
	if err != nil {
		log.Printf("gw: deny (bad jwt) device=%s: %v", peer.Subject.CommonName, err)
		conn.Write([]byte{proto.StatusDeny})
		return
	}
	if claims.CertThumbprint != authjwt.Thumbprint(peer) {
		log.Printf("gw: deny (thumbprint mismatch) cert_cn=%s jwt_device=%s", peer.Subject.CommonName, claims.DeviceID)
		conn.Write([]byte{proto.StatusDeny})
		return
	}

	if !g.currentPolicy().Evaluate(claims.DeviceID, req.Resource) {
		log.Printf("gw: deny (policy) device=%s resource=%s", claims.DeviceID, req.Resource)
		conn.Write([]byte{proto.StatusDeny})
		return
	}

	backendAddr, ok := g.Backends[req.Resource]
	if !ok {
		log.Printf("gw: deny (unknown resource) resource=%s", req.Resource)
		conn.Write([]byte{proto.StatusDeny})
		return
	}
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("gw: deny (backend dial failed) resource=%s: %v", req.Resource, err)
		conn.Write([]byte{proto.StatusDeny})
		return
	}
	defer backend.Close()

	if _, err := conn.Write([]byte{proto.StatusAllow}); err != nil {
		return
	}
	log.Printf("gw: allow device=%s resource=%s", claims.DeviceID, req.Resource)
	gwproxy.Pipe(conn, backend)
}

// Serve accepts connections on ln and handles each with HandleConn in its
// own goroutine, until ln is closed.
func Serve(ln net.Listener, g *Gateway) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			continue
		}
		go g.HandleConn(tlsConn)
	}
}

// TLSListener opens an mTLS listener: server identity is serverCert,
// client certs are required and must chain to caPool.
func TLSListener(addr string, serverCert tls.Certificate, caPool *x509.CertPool) (net.Listener, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}
	return tls.Listen("tcp", addr, cfg)
}
