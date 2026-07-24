package main

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cyc0logy/ztna/internal/gwproxy"
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

	gwproxy.Pipe(conn, stdio{})
	return nil
}

type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return nil }
