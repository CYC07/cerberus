// Package proto defines the small framed protocol ztnactl speaks to
// ztna-gw after the mTLS handshake completes: a resource name and a JWT,
// each length-prefixed, followed by a single-byte allow/deny response.
package proto

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	StatusDeny  byte = 0x00
	StatusAllow byte = 0x01
)

// maxFrameSize bounds a single frame (resource name or JWT) well above any
// real value, to reject obviously malicious oversized length prefixes.
// Set to the max value representable in uint16 to avoid truncation.
const maxFrameSize = (1 << 16) - 1 // 65535

var ErrFrameTooLarge = errors.New("proto: frame exceeds max size")

// WriteFrame writes a uint16-length-prefixed byte frame.
func WriteFrame(w io.Writer, data []byte) error {
	if len(data) > maxFrameSize {
		return ErrFrameTooLarge
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFrame reads a uint16-length-prefixed byte frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ConnectRequest is what ztnactl sends immediately after the mTLS
// handshake completes, before any raw proxied bytes.
type ConnectRequest struct {
	Resource string
	JWT      string
}

// WriteConnectRequest frames and writes a ConnectRequest.
func WriteConnectRequest(w io.Writer, req ConnectRequest) error {
	if err := WriteFrame(w, []byte(req.Resource)); err != nil {
		return err
	}
	return WriteFrame(w, []byte(req.JWT))
}

// ReadConnectRequest reads a framed ConnectRequest.
func ReadConnectRequest(r io.Reader) (ConnectRequest, error) {
	resource, err := ReadFrame(r)
	if err != nil {
		return ConnectRequest{}, err
	}
	token, err := ReadFrame(r)
	if err != nil {
		return ConnectRequest{}, err
	}
	return ConnectRequest{Resource: string(resource), JWT: string(token)}, nil
}
