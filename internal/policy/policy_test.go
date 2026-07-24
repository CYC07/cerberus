package policy_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyc0logy/ztna/internal/policy"
)

func TestEvaluate_AllowsMatchingRule(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{Subject: "device-a", Resource: "ssh-homepc", Action: "allow"},
	})
	require.True(t, e.Evaluate("device-a", "ssh-homepc"))
}

func TestEvaluate_DeniesExplicitDenyRule(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{Subject: "device-a", Resource: "ssh-homepc", Action: "deny"},
	})
	require.False(t, e.Evaluate("device-a", "ssh-homepc"))
}

func TestEvaluate_DefaultDeniesUnknownSubject(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{Subject: "device-a", Resource: "ssh-homepc", Action: "allow"},
	})
	require.False(t, e.Evaluate("device-b", "ssh-homepc"))
}

func TestEvaluate_DefaultDeniesUnknownResource(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{Subject: "device-a", Resource: "ssh-homepc", Action: "allow"},
	})
	require.False(t, e.Evaluate("device-a", "other-resource"))
}

func TestEvaluate_EmptyEngineDeniesEverything(t *testing.T) {
	e := policy.NewEngine(nil)
	require.False(t, e.Evaluate("device-a", "ssh-homepc"))
}
