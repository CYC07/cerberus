package mesh

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// BuildUAPIConfig renders a wireguard-go IpcSet configuration string for
// the local device's private key, listen port, and full peer set. Always
// emits replace_peers=true — callers apply an entire computed netmap
// atomically in one IpcSet call rather than diffing individual peers in
// and out (see internal/mesh/device.go, added in Plan 2B).
//
// A peer with an empty Endpoint gets no endpoint= line at all —
// wireguard-go treats a present-but-empty endpoint as a configuration
// error, and an empty Endpoint here just means this device may be waiting
// for the peer to initiate the handshake (WireGuard's own endpoint
// roaming then learns it from the first received packet). At least one
// side of any communicating pair must have a non-empty Endpoint, or
// neither side can ever send the first packet — see BuildNetmap's doc
// comment and the design spec for the full invariant.
//
// The UAPI config protocol (https://www.wireguard.com/xplatform/) uses
// lowercase hex-encoded keys, not the base64 form wgtypes.Key.String()
// returns (that's the `wg` CLI display format) — this function hex-encodes
// at this boundary so every other layer can keep using the base64 form.
func BuildUAPIConfig(privateKey wgtypes.Key, listenPort int, peers []DeviceView) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	b.WriteString("replace_peers=true\n")
	for _, p := range peers {
		pub, err := wgtypes.ParseKey(p.Pubkey)
		if err != nil {
			return "", fmt.Errorf("mesh: peer %s: invalid pubkey: %w", p.DeviceID, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		fmt.Fprintf(&b, "allowed_ip=%s/32\n", p.MeshIP)
	}
	return b.String(), nil
}
