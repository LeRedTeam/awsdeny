package parse

import (
	"regexp"
	"strings"
)

// extractNamedGroups extracts named capture groups from a regex match.
func extractNamedGroups(re *regexp.Regexp, s string) map[string]string {
	match := re.FindStringSubmatch(s)
	if match == nil {
		return nil
	}
	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" && i < len(match) {
			result[name] = match[i]
		}
	}
	return result
}

// normalizePolicyType converts AWS error message policy type strings to short form.
func normalizePolicyType(raw string) string {
	if pt, ok := policyTypeMap[strings.ToLower(raw)]; ok {
		return pt
	}
	return raw
}

// normalizeDenyType normalizes deny type strings.
func normalizeDenyType(raw string) string {
	switch strings.ToLower(raw) {
	case "explicit deny":
		return "explicit"
	case "implicit deny":
		return "implicit"
	default:
		return raw
	}
}

// inferActionFromOperation maps an AWS API operation name to an IAM action.
func inferActionFromOperation(operation string) string {
	if action, ok := operationToAction[operation]; ok {
		return action
	}
	return ""
}

// extractAccountFromARN extracts the account ID from an ARN.
func extractAccountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// extractRegionFromARN extracts the region from an ARN.
func extractRegionFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// inferPolicyTypeFromReason tries to extract policy type from "because" reason text.
func inferPolicyTypeFromReason(reason string) string {
	groups := extractNamedGroups(reReasonNoPolicy, reason)
	if groups == nil {
		return ""
	}
	return normalizePolicyType(groups["policy_type"])
}

// inferDenyTypeFromReason tries to determine deny type from "because" reason text.
func inferDenyTypeFromReason(reason string) string {
	lower := strings.ToLower(reason)
	if strings.Contains(lower, "no identity-based policy allows") ||
		strings.Contains(lower, "no resource-based policy allows") {
		return "implicit"
	}
	if strings.Contains(lower, "explicit deny") {
		return "explicit"
	}
	return ""
}
