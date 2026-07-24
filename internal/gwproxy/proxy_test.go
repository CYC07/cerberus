package gwproxy_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CYC07/cerberus/internal/gwproxy"
)

func TestPipe_CopiesBothDirections(t *testing.T) {
	aClient, aServer := net.Pipe()
	bClient, bServer := net.Pipe()

	done := make(chan struct{})
	go func() {
		gwproxy.Pipe(aServer, bServer)
		close(done)
	}()

	go func() {
		buf := make([]byte, 5)
		io.ReadFull(bClient, buf)
		bClient.Write(buf)
	}()

	_, err := aClient.Write([]byte("hello"))
	require.NoError(t, err)

	reply := make([]byte, 5)
	aClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(aClient, reply)
	require.NoError(t, err)
	require.Equal(t, "hello", string(reply))

	aClient.Close()
	bClient.Close()
	<-done
}

func TestPipe_TerminatesWhenOneSideClosed(t *testing.T) {
	aClient, aServer := net.Pipe()
	bClient, bServer := net.Pipe()

	done := make(chan struct{})
	go func() {
		gwproxy.Pipe(aServer, bServer)
		close(done)
	}()

	// Close only bClient (the remote side), leaving aClient open/idle.
	// This simulates a backend disconnect while the client is idle.
	// If Pipe's internal Close calls don't work correctly, Pipe will
	// never return and we will hit the timeout.
	bClient.Close()

	select {
	case <-done:
		// Pipe returned — internal close propagated correctly
	case <-time.After(2 * time.Second):
		t.Fatal("Pipe did not return after one side closed — likely goroutine leak")
	}

	// Clean up
	aClient.Close()
}
