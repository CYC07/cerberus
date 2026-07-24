package gwproxy_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyc0logy/ztna/internal/gwproxy"
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
