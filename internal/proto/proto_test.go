package proto_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/proto"
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

// TestWriteFrame_MaxSizeBoundary tests the off-by-one boundary condition.
// Ensures that frames of exactly maxFrameSize bytes (65535) succeed and
// frames of maxFrameSize+1 bytes (65536) fail with ErrFrameTooLarge.
func TestWriteFrame_MaxSizeBoundary(t *testing.T) {
	tests := []struct {
		name      string
		dataSize  int
		wantError bool
	}{
		{
			name:      "just under max",
			dataSize:  65534,
			wantError: false,
		},
		{
			name:      "exactly max size (65535)",
			dataSize:  65535,
			wantError: false,
		},
		{
			name:      "one byte over max",
			dataSize:  65536,
			wantError: true,
		},
		{
			name:      "well over max",
			dataSize:  100000,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			for i := range data {
				data[i] = byte(i % 256)
			}

			var buf bytes.Buffer
			err := proto.WriteFrame(&buf, data)

			if tt.wantError {
				require.ErrorIs(t, err, proto.ErrFrameTooLarge)
				require.Zero(t, buf.Len(), "should not write anything on error")
				return
			}

			require.NoError(t, err)

			// Verify the frame can be read back correctly (round-trip).
			readBack, err := proto.ReadFrame(&buf)
			require.NoError(t, err)
			require.Equal(t, data, readBack, "frame should round-trip correctly")
		})
	}
}

// TestWriteConnectRequest_ResourceTooLarge tests that oversized resource names fail.
func TestWriteConnectRequest_ResourceTooLarge(t *testing.T) {
	var buf bytes.Buffer
	req := proto.ConnectRequest{
		Resource: string(make([]byte, 65536)), // one byte over max
		JWT:      "valid.jwt.token",
	}

	err := proto.WriteConnectRequest(&buf, req)
	require.ErrorIs(t, err, proto.ErrFrameTooLarge)
	require.Zero(t, buf.Len(), "should not write anything on error")
}

// TestWriteConnectRequest_JWTTooLarge tests that oversized JWT tokens fail.
func TestWriteConnectRequest_JWTTooLarge(t *testing.T) {
	var buf bytes.Buffer
	req := proto.ConnectRequest{
		Resource: "valid-resource",
		JWT:      string(make([]byte, 65536)), // one byte over max
	}

	err := proto.WriteConnectRequest(&buf, req)
	// The resource frame writes successfully, but JWT frame should fail.
	require.ErrorIs(t, err, proto.ErrFrameTooLarge)
}

// TestWriteFrame_MaxSizeRoundTrip verifies that the maximum allowed frame size
// correctly round-trips without truncation (regression test for uint16 overflow).
func TestWriteFrame_MaxSizeRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	maxData := make([]byte, 65535)
	for i := range maxData {
		maxData[i] = byte((i * 17) % 256) // deterministic pattern
	}

	err := proto.WriteFrame(&buf, maxData)
	require.NoError(t, err)

	// Read it back and verify no truncation occurred.
	readBack, err := proto.ReadFrame(&buf)
	require.NoError(t, err)
	require.Len(t, readBack, 65535)
	require.Equal(t, maxData, readBack)
}
