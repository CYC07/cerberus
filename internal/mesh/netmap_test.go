package mesh_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/mesh"
	"github.com/CYC07/cerberus/internal/policy"
	"github.com/CYC07/cerberus/internal/store"
)

func testDevices() []store.MeshDevice {
	return []store.MeshDevice{
		{DeviceID: "a", WGPubkey: "pub-a", MeshIP: "100.64.0.1"},
		{DeviceID: "b", WGPubkey: "pub-b", MeshIP: "100.64.0.2"},
		{DeviceID: "c", WGPubkey: "pub-c", MeshIP: "100.64.0.3", Revoked: true},
	}
}

func TestBuildNetmap_NoPolicyExcludesEverything(t *testing.T) {
	eng := policy.NewEngine(nil)
	nm := mesh.BuildNetmap("a", testDevices(), eng)
	require.Equal(t, "a", nm.Self.DeviceID)
	require.Empty(t, nm.Peers)
}

func TestBuildNetmap_GrantIsBidirectional(t *testing.T) {
	eng := policy.NewEngine([]policy.Rule{{Subject: "a", Resource: "mesh:b", Action: "allow"}})

	nmA := mesh.BuildNetmap("a", testDevices(), eng)
	require.Len(t, nmA.Peers, 1)
	require.Equal(t, "b", nmA.Peers[0].DeviceID)

	nmB := mesh.BuildNetmap("b", testDevices(), eng)
	require.Len(t, nmB.Peers, 1)
	require.Equal(t, "a", nmB.Peers[0].DeviceID)
}

func TestBuildNetmap_ExcludesRevokedPeerEvenWithGrant(t *testing.T) {
	eng := policy.NewEngine([]policy.Rule{{Subject: "a", Resource: "mesh:c", Action: "allow"}})
	nm := mesh.BuildNetmap("a", testDevices(), eng)
	require.Empty(t, nm.Peers)
}

func TestBuildNetmap_RevokedSelfYieldsEmptyNetmap(t *testing.T) {
	eng := policy.NewEngine([]policy.Rule{{Subject: "b", Resource: "mesh:c", Action: "allow"}})
	nm := mesh.BuildNetmap("c", testDevices(), eng)
	require.Equal(t, mesh.Netmap{}, nm)
}

func TestBuildNetmap_UnknownSelfYieldsEmptyNetmap(t *testing.T) {
	eng := policy.NewEngine(nil)
	nm := mesh.BuildNetmap("nobody", testDevices(), eng)
	require.Equal(t, mesh.Netmap{}, nm)
}

func TestBuildNetmap_SelfNeverInOwnPeers(t *testing.T) {
	eng := policy.NewEngine([]policy.Rule{{Subject: "a", Resource: "mesh:a", Action: "allow"}})
	nm := mesh.BuildNetmap("a", testDevices(), eng)
	require.Empty(t, nm.Peers)
}
