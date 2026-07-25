// Package mesh implements Cerberus's optional WireGuard full L3 mesh: a
// second, opt-in data plane alongside the existing mTLS broker.
// Device-level reachability is granted the same way as the broker — via
// internal/policy's default-deny engine — through "mesh:<device_id>"
// resources. See docs/superpowers/specs/2026-07-25-wireguard-mesh-design.md
// for the full design.
package mesh

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// KeyPair is a WireGuard X25519 keypair. Kept separate from the project's
// ECDSA P-256 CA / Ed25519 JWT signing key material — WireGuard's Noise
// protocol requires Curve25519 keys, so this is a distinct credential
// generated fresh per device, never derived from the mTLS identity.
type KeyPair struct {
	Private wgtypes.Key
	Public  wgtypes.Key
}

// GenerateKeyPair creates a fresh WireGuard keypair.
func GenerateKeyPair() (KeyPair, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}
