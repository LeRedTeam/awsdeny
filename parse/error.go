package parse

import (
	"strings"

	"github.com/leredteam/awsdeny/internal"
)

// Parse takes a raw AccessDenied error string and extracts structured information.
// It tries patterns from most specific to least specific, returning the best match.
func Parse(raw string) internal.ParsedError {
	raw = strings.TrimSpace(raw)
	parsed := internal.ParsedError{
		RawMessage: raw,
		ParseLevel: 1,
	}

	// Try to unwrap AWS CLI wrapper first (Format G)
	innerMessage := raw
	if groups := extractNamedGroups(reCLIWrapper, raw); groups != nil {
		parsed.ErrorCode = groups["error_code"]
		parsed.Operation = groups["operation"]
		innerMessage = groups["message"]

		// Infer action from operation name if we can
		if action := inferActionFromOperation(parsed.Operation); action != "" && parsed.Action == "" {
			parsed.Action = action
		}
	}

	// Try Format I: Enriched with policy ARN (most specific)
	if groups := extractNamedGroups(reEnrichedWithPolicyARN, innerMessage); groups != nil {
		parsed.Format = "I"
		parsed.Principal = groups["principal"]
		parsed.Action = groups["action"]
		parsed.Resource = groups["resource"]
		parsed.DenyType = normalizeDenyType(groups["deny_type"])
		parsed.PolicyType = normalizePolicyType(groups["policy_type"])
		parsed.PolicyARN = groups["policy_arn"]
		return parsed
	}

	// Try Format B: Enriched with policy type
	if groups := extractNamedGroups(reEnrichedDeny, innerMessage); groups != nil {
		parsed.Format = "B"
		parsed.Principal = groups["principal"]
		parsed.Action = groups["action"]
		parsed.Resource = groups["resource"]
		parsed.DenyType = normalizeDenyType(groups["deny_type"])
		parsed.PolicyType = normalizePolicyType(groups["policy_type"])
		return parsed
	}

	// Try Format C: Enriched with reason
	if groups := extractNamedGroups(reEnrichedReason, innerMessage); groups != nil {
		parsed.Format = "C"
		parsed.Principal = groups["principal"]
		parsed.Action = groups["action"]
		parsed.Resource = groups["resource"]
		parsed.Reason = groups["reason"]

		// Try to infer deny type and policy type from reason
		if dt := inferDenyTypeFromReason(parsed.Reason); dt != "" {
			parsed.DenyType = dt
		}
		if pt := inferPolicyTypeFromReason(parsed.Reason); pt != "" {
			parsed.PolicyType = pt
		}
		return parsed
	}

	// Try Format A: Classic
	if groups := extractNamedGroups(reClassic, innerMessage); groups != nil {
		parsed.Format = "A"
		parsed.Principal = groups["principal"]
		parsed.Action = groups["action"]
		parsed.Resource = groups["resource"]
		return parsed
	}

	// Try Format D: EC2 Encoded
	if groups := extractNamedGroups(reEC2Encoded, innerMessage); groups != nil {
		parsed.Format = "D"
		parsed.EncodedMessage = groups["encoded"]
		return parsed
	}

	// Format E: S3 Minimal / bare "Access Denied"
	if reS3Minimal.MatchString(strings.TrimSpace(innerMessage)) {
		parsed.Format = "E"
		return parsed
	}

	// If we had a CLI wrapper, we still extracted something useful
	if parsed.ErrorCode != "" || parsed.Operation != "" {
		parsed.Format = "G"
		return parsed
	}

	// Last resort: try to extract anything useful from the raw string
	parsed.Format = "unknown"
	if principals := rePrincipal.FindString(innerMessage); principals != "" {
		parsed.Principal = principals
	}
	if actions := reAction.FindString(innerMessage); actions != "" {
		parsed.Action = actions
	}
	return parsed
}
