package mesh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAssignAddress_RejectsInvalidCIDR is the one part of device.go
// testable without root: the input-validation guard runs before
// AssignAddress ever touches d.dev or shells out to `ip`, so a Device
// with only its name field set is enough. Everything past this guard
// needs CAP_NET_ADMIN and is covered by the manual verification runbook
// in this plan (Task 5) instead.
func TestAssignAddress_RejectsInvalidCIDR(t *testing.T) {
	d := &Device{name: "test0"}
	err := d.AssignAddress("not-a-cidr")
	// ErrorContains, not just Error: proves the netip.ParsePrefix guard
	// fired, not some other failure — d.dev is nil on this bare Device, so
	// anything past the guard would nil-panic before returning an error.
	require.ErrorContains(t, err, "invalid mesh address")
}
