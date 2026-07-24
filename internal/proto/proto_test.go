package proto_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyc0logy/ztna/internal/proto"
)

func TestConnectRequest_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	want := proto.ConnectRequest{Resource: "ssh-homepc", JWT: "header.payload.sig"}

	err := proto.WriteConnectRequest(&buf, want)
	require.NoError(t, err)

	got, err := proto.ReadConnectRequest(&buf)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestConnectRequest_EmptyFields(t *testing.T) {
	var buf bytes.Buffer
	want := proto.ConnectRequest{Resource: "", JWT: ""}

	err := proto.WriteConnectRequest(&buf, want)
	require.NoError(t, err)

	got, err := proto.ReadConnectRequest(&buf)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestReadConnectRequest_TruncatedInputFails(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x05, 'h', 'e'}) // claims 5 bytes, has 2
	_, err := proto.ReadConnectRequest(buf)
	require.Error(t, err)
}
