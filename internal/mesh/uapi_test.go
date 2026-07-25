package mesh_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/mesh"
)

func TestBuildUAPIConfig_KeysAreHexNotBase64(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	cfg, err := mesh.BuildUAPIConfig(kp.Private, 51820, nil)
	require.NoError(t, err)
	require.Contains(t, cfg, "private_key="+hex.EncodeToString(kp.Private[:])+"\n")
	require.NotContains(t, cfg, kp.Private.String()) // base64 form must never appear
}

func TestBuildUAPIConfig_OmitsEmptyEndpoint(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	peerKP, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	cfg, err := mesh.BuildUAPIConfig(kp.Private, 51820, []mesh.DeviceView{
		{DeviceID: "b", Pubkey: peerKP.Public.String(), MeshIP: "100.64.0.2"},
	})
	require.NoError(t, err)
	require.NotContains(t, cfg, "endpoint=")
	require.Contains(t, cfg, "allowed_ip=100.64.0.2/32\n")
	require.Contains(t, cfg, "public_key="+hex.EncodeToString(peerKP.Public[:])+"\n")
	require.NotContains(t, cfg, peerKP.Public.String()) // base64 form must never appear
}

func TestBuildUAPIConfig_IncludesNonEmptyEndpoint(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	peerKP, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	cfg, err := mesh.BuildUAPIConfig(kp.Private, 51820, []mesh.DeviceView{
		{DeviceID: "b", Pubkey: peerKP.Public.String(), MeshIP: "100.64.0.2", Endpoint: "1.2.3.4:51820"},
	})
	require.NoError(t, err)
	require.Contains(t, cfg, "endpoint=1.2.3.4:51820\n")
}

func TestBuildUAPIConfig_AlwaysReplacesPeers(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	cfg, err := mesh.BuildUAPIConfig(kp.Private, 51820, nil)
	require.NoError(t, err)
	require.Contains(t, cfg, "replace_peers=true\n")
}

func TestBuildUAPIConfig_ListenPort(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	cfg, err := mesh.BuildUAPIConfig(kp.Private, 51820, nil)
	require.NoError(t, err)
	require.Contains(t, cfg, "listen_port=51820\n")
}

func TestBuildUAPIConfig_InvalidPeerPubkeyErrors(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	_, err = mesh.BuildUAPIConfig(kp.Private, 51820, []mesh.DeviceView{
		{DeviceID: "b", Pubkey: "not-a-valid-key", MeshIP: "100.64.0.2"},
	})
	require.Error(t, err)
}
