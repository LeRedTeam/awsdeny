package enrich

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/leredteam/awsdeny/internal"
)

// policyDocument represents an IAM policy JSON document.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []json.RawMessage `json:"Statement"`
}

// policyStatementRaw represents a single policy statement with flexible types.
type policyStatementRaw struct {
	Sid       string                            `json:"Sid"`
	Effect    string                            `json:"Effect"`
	Action    interface{}                       `json:"Action"`
	NotAction interface{}                       `json:"NotAction"`
	Resource  interface{}                       `json:"Resource"`
	Condition map[string]map[string]interface{} `json:"Condition"`
}

// parsePolicyDocument parses a JSON policy document into structured statements.
func parsePolicyDocument(document string) ([]internal.PolicyStatement, error) {
	var doc policyDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, err
	}

	var statements []internal.PolicyStatement
	for _, raw := range doc.Statement {
		var stmt policyStatementRaw
		if err := json.Unmarshal(raw, &stmt); err != nil {
			continue
		}

		ps := internal.PolicyStatement{
			Sid:        stmt.Sid,
			Effect:     stmt.Effect,
			Actions:    toStringSlice(stmt.Action),
			NotActions: toStringSlice(stmt.NotAction),
			Resources:  toStringSlice(stmt.Resource),
		}

		if stmt.Condition != nil {
			ps.Conditions = make(map[string]map[string][]string)
			for op, keys := range stmt.Condition {
				ps.Conditions[op] = make(map[string][]string)
				for key, val := range keys {
					ps.Conditions[op][key] = toStringSlice(val)
				}
			}
		}

		statements = append(statements, ps)
	}

	return statements, nil
}

// toStringSlice converts a JSON value that can be either a string or []string.
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// FindMatchingStatements finds statements in a policy that match the given action and resource.
func FindMatchingStatements(statements []internal.PolicyStatement, action, resource string) []internal.PolicyStatement {
	var matches []internal.PolicyStatement
	for _, stmt := range statements {
		if matchesStatement(stmt, action, resource) {
			matches = append(matches, stmt)
		}
	}
	return matches
}

func matchesStatement(stmt internal.PolicyStatement, action, resource string) bool {
	if action == "" {
		return false
	}
	actionMatch := false

	if len(stmt.Actions) > 0 {
		// Action: match if any pattern matches
		for _, a := range stmt.Actions {
			if matchActionPattern(a, action) {
				actionMatch = true
				break
			}
		}
	} else if len(stmt.NotActions) > 0 {
		// NotAction: match if the action is NOT in the exclusion list
		excluded := false
		for _, a := range stmt.NotActions {
			if matchActionPattern(a, action) {
				excluded = true
				break
			}
		}
		actionMatch = !excluded
	}

	if !actionMatch {
		return false
	}

	if len(stmt.Resources) == 0 {
		return true
	}

	for _, r := range stmt.Resources {
		if matchResourcePattern(r, resource) {
			return true
		}
	}
	return false
}

// matchActionPattern checks if an IAM action pattern matches an action.
// Actions are case-insensitive in IAM.
func matchActionPattern(pattern, action string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(strings.ToLower(action), strings.ToLower(strings.TrimSuffix(pattern, "*")))
	}
	return strings.EqualFold(pattern, action)
}

// matchResourcePattern checks if an IAM resource pattern matches a resource ARN.
// Resource ARNs contain case-sensitive components (e.g., S3 object keys).
func matchResourcePattern(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == resource
}

// AnalyzeStatements analyzes matched statements to determine the cause of denial.
func AnalyzeStatements(statements []internal.PolicyStatement, action, resource string) (string, string) {
	for _, stmt := range statements {
		if strings.EqualFold(stmt.Effect, "Deny") && matchesStatement(stmt, action, resource) {
			if len(stmt.Conditions) > 0 {
				reason := "Potential explicit deny (has conditions that may not apply to your request): " + formatConditions(stmt.Conditions)
				if stmt.Sid != "" {
					reason = "Statement '" + stmt.Sid + "': " + reason
				}
				return "conditional", reason
			}
			reason := "Explicit deny statement found"
			if stmt.Sid != "" {
				reason = "Statement '" + stmt.Sid + "': " + reason
			}
			return "explicit", reason
		}
	}

	// No explicit deny found — check for missing allow
	hasAllow := false
	for _, stmt := range statements {
		if strings.EqualFold(stmt.Effect, "Allow") && matchesStatement(stmt, action, resource) {
			hasAllow = true
			break
		}
	}
	if !hasAllow {
		return "implicit", "No Allow statement matches this action and resource"
	}

	return "unknown", "Policy analysis inconclusive"
}

func formatConditions(conditions map[string]map[string][]string) string {
	// Sort operators for deterministic output
	ops := make([]string, 0, len(conditions))
	for op := range conditions {
		ops = append(ops, op)
	}
	sort.Strings(ops)

	var parts []string
	for _, op := range ops {
		keys := make([]string, 0, len(conditions[op]))
		for key := range conditions[op] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			parts = append(parts, op+"("+key+" = "+strings.Join(conditions[op][key], ", ")+")")
		}
	}
	return strings.Join(parts, "; ")
}
