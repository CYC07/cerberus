// Package policy implements a default-deny allow/deny rule engine mapping
// (subject, resource) pairs to an access decision.
package policy

// Rule is one policy entry: whether subject may access resource.
type Rule struct {
	Subject  string
	Resource string
	Action   string // "allow" or "deny"
}

// Engine evaluates access decisions against a fixed rule set.
type Engine struct {
	rules []Rule
}

// NewEngine builds an Engine from rules. A nil or empty rule set denies
// everything.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Evaluate returns true only if an explicit "allow" rule matches subject
// and resource. Absence of a matching rule, or an explicit "deny" rule,
// both result in false — default-deny.
func (e *Engine) Evaluate(subject, resource string) bool {
	for _, r := range e.rules {
		if r.Subject == subject && r.Resource == resource {
			return r.Action == "allow"
		}
	}
	return false
}
