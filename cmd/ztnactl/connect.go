package main

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cyc0logy/ztna/internal/proto"
)

func cmdConnect(stateDir, gwAddr, resource string) error {
	cert, err := loadClientCert(stateDir)
	if err != nil {
		return err
	}
	pool, err := loadCAPool(stateDir)
	if err != nil {
		return err
	}
	tokenBytes, err := os.ReadFile(filepath.Join(stateDir, "token.jwt"))
	if err != nil {
		return err
	}

	conn, err := tls.Dial("tcp", gwAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := proto.WriteConnectRequest(conn, proto.ConnectRequest{
		Resource: resource,
		JWT:      string(tokenBytes),
	}); err != nil {
		return err
	}

	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		return err
	}
	if status[0] != proto.StatusAllow {
		return errors.New("connection denied")
	}

	// Pipe stdin <-> conn, but exit as soon as remote closes (doesn't wait for stdin EOF).
	// Direct io.Copy avoids gwproxy.Pipe's symmetric wg.Wait() which would block
	// forever waiting for stdin to also close.
	done := make(chan struct{})
	go func() {
		io.Copy(os.Stdout, conn)
		close(done)
	}()
	go func() {
		io.Copy(conn, os.Stdin)
	}()
	<-done
	return nil
}
