package mesh_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/mesh"
)

func TestGenerateKeyPair_PublicMatchesPrivate(t *testing.T) {
	kp, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	require.Equal(t, kp.Private.PublicKey(), kp.Public)
}

func TestGenerateKeyPair_NoCollisions(t *testing.T) {
	a, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	b, err := mesh.GenerateKeyPair()
	require.NoError(t, err)
	require.NotEqual(t, a.Private, b.Private)
	require.NotEqual(t, a.Public, b.Public)
}
