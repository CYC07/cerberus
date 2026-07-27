package mesh

import (
	"fmt"
	"net/netip"
	"os/exec"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Device wraps a running wireguard-go interface: a real kernel TUN plus
// the userspace WireGuard protocol engine bound to it. Creating one
// requires CAP_NET_ADMIN (root on Linux) — this is the only file in
// internal/mesh that can't run under `go test ./...`; it's kept as thin
// as possible so the logic it calls (BuildUAPIConfig, BuildNetmap) stays
// independently testable in keys_test.go, netmap_test.go, uapi_test.go.
type Device struct {
	dev  *device.Device
	name string
}

// Up creates a TUN interface named ifaceName, brings up a wireguard-go
// engine bound to it with privateKey listening on listenPort, and returns
// the running Device. Requires root.
func Up(ifaceName string, privateKey wgtypes.Key, listenPort int) (*Device, error) {
	tunDev, err := tun.CreateTUN(ifaceName, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("mesh: create tun %s: %w", ifaceName, err)
	}
	logger := device.NewLogger(device.LogLevelError, "mesh: ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	cfg, err := BuildUAPIConfig(privateKey, listenPort, nil)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("mesh: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("mesh: bring up device: %w", err)
	}
	return &Device{dev: dev, name: ifaceName}, nil
}

// ApplyNetmap replaces the device's full peer set in one atomic IpcSet
// call (BuildUAPIConfig always emits replace_peers=true). Safe to call
// repeatedly with the same peers — idempotent.
func (d *Device) ApplyNetmap(privateKey wgtypes.Key, listenPort int, peers []DeviceView) error {
	cfg, err := BuildUAPIConfig(privateKey, listenPort, peers)
	if err != nil {
		return err
	}
	return d.dev.IpcSet(cfg)
}

// AssignAddress assigns cidr (e.g. "100.64.0.2/32") to the TUN interface
// at the OS level and brings the link up. Linux only; requires root.
//
// cidr must parse as a valid IPv4 prefix before it's used to build an
// exec.Command argument — mesh_ip arrives over the network from
// cerberus-ctrl and, even though it's the same operator's infrastructure,
// gets validated like any other value crossing a process boundary before
// it reaches a shelled-out command.
func (d *Device) AssignAddress(cidr string) error {
	if _, err := netip.ParsePrefix(cidr); err != nil {
		return fmt.Errorf("mesh: invalid mesh address %q: %w", cidr, err)
	}
	if out, err := exec.Command("ip", "addr", "add", cidr, "dev", d.name).CombinedOutput(); err != nil {
		return fmt.Errorf("mesh: ip addr add: %w: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", d.name, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("mesh: ip link set up: %w: %s", err, out)
	}
	return nil
}

// Close tears down the WireGuard engine and its TUN interface.
func (d *Device) Close() {
	d.dev.Close()
}
