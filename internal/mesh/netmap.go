package mesh

import (
	"github.com/CYC07/cerberus/internal/policy"
	"github.com/CYC07/cerberus/internal/store"
)

// DeviceView is the wire-format projection of a mesh device: what a
// polling device needs to know about itself or a peer. Endpoint is empty
// if the device hasn't reported one.
type DeviceView struct {
	DeviceID string `json:"device_id"`
	Pubkey   string `json:"wg_pubkey"`
	MeshIP   string `json:"mesh_ip"`
	Endpoint string `json:"endpoint,omitempty"`
}

// Netmap is what /mesh returns to a polling device: its own mesh identity
// plus the peer set it's authorized to reach.
type Netmap struct {
	Self  DeviceView   `json:"self"`
	Peers []DeviceView `json:"peers"`
}

// BuildNetmap computes the netmap for device `self`: its own DeviceView
// plus every other non-revoked mesh device it's authorized to reach.
//
// Reachability is bidirectional at the WireGuard layer even though policy
// grants are directional: WireGuard requires both ends of a tunnel to
// configure each other as a peer for the handshake to complete, so a
// single AddPolicy(subject=A, resource="mesh:B", action="allow") grant
// makes B reachable from A *and* makes A reachable from B. Fine-grained,
// one-directional enforcement still happens in the existing mTLS broker;
// mesh only ever grants device-level L3 reachability. This is a
// deliberate MVP simplification, documented in the design spec and the
// project README.
//
// self is never included in its own Peers. Revoked devices are excluded
// even if a policy rule still names them. An unknown or revoked self
// yields a zero Netmap.
func BuildNetmap(self string, devices []store.MeshDevice, eng *policy.Engine) Netmap {
	byID := make(map[string]store.MeshDevice, len(devices))
	for _, d := range devices {
		byID[d.DeviceID] = d
	}
	selfDev, ok := byID[self]
	if !ok || selfDev.Revoked {
		return Netmap{}
	}

	nm := Netmap{Self: toView(selfDev)}
	for _, d := range devices {
		if d.DeviceID == self || d.Revoked {
			continue
		}
		if eng.Evaluate(self, "mesh:"+d.DeviceID) || eng.Evaluate(d.DeviceID, "mesh:"+self) {
			nm.Peers = append(nm.Peers, toView(d))
		}
	}
	return nm
}

func toView(d store.MeshDevice) DeviceView {
	return DeviceView{DeviceID: d.DeviceID, Pubkey: d.WGPubkey, MeshIP: d.MeshIP, Endpoint: d.MeshEndpoint}
}
