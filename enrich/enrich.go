package enrich

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/leredteam/awsdeny/internal"
)

// Enrich performs Level 2-3 enrichment on a parsed error.
// It gracefully degrades: if any API call fails, it continues with what it has.
func Enrich(ctx context.Context, client *Client, parsed internal.ParsedError) *internal.EnrichmentResult {
	result := &internal.EnrichmentResult{}

	// Level 2: Policy Fetch
	if parsed.PolicyARN != "" {
		doc, statements, err := client.FetchPolicy(ctx, parsed.PolicyARN)
		if err != nil {
			result.Warnings = append(result.Warnings,
				"Enrichment failed: "+err.Error()+". Ensure your AWS credentials have iam:GetPolicy permission.")
		} else {
			result.PolicyFetched = true
			result.PolicyDocument = doc
			result.MatchingStatements = FindMatchingStatements(statements, parsed.Action, parsed.Resource)

			if len(result.MatchingStatements) > 0 {
				denyType, reason := AnalyzeStatements(result.MatchingStatements, parsed.Action, parsed.Resource)
				result.PolicyDenyType = denyType
				result.PolicyDenyReason = reason
			}
		}
	}

	// Level 2.5a: Decode EC2 encoded message
	if parsed.EncodedMessage != "" {
		decoded, err := client.DecodeAuthorizationMessage(ctx, parsed.EncodedMessage)
		if err != nil {
			result.Warnings = append(result.Warnings,
				"Could not decode EC2 authorization message: "+err.Error())
		} else {
			result.DecodedMessage = decoded
		}
	}

	// Level 2.5b: Principal introspection for implicit denies
	if parsed.Principal != "" && (parsed.DenyType == "implicit" || parsed.PolicyType == "identity") {
		roleName := extractRoleNameFromARN(parsed.Principal)
		if roleName != "" {
			policies, err := client.ListAttachedRolePolicies(ctx, roleName)
			if err != nil {
				result.Warnings = append(result.Warnings, "Could not list role policies: "+err.Error())
			} else if len(policies) > 0 {
				result.AttachedPolicies = policies
			}
		}
	}

	// Level 2.5c: Rank attached policies by closeness to granting
	if len(result.AttachedPolicies) > 0 && parsed.Action != "" {
		closest, err := findClosestPolicy(ctx, client, result.AttachedPolicies, parsed.Action, parsed.Resource)
		if err != nil {
			result.Warnings = append(result.Warnings, "Could not analyze attached policies: "+err.Error())
		} else if closest != nil {
			result.ClosestPolicy = closest
		}
	}

	// Level 3: Simulation
	if parsed.Principal != "" && parsed.Action != "" {
		var contextEntries []iamtypes.ContextEntry
		if parsed.SourceIP != "" {
			contextEntries = append(contextEntries, iamtypes.ContextEntry{
				ContextKeyName:   aws.String("aws:SourceIp"),
				ContextKeyType:   iamtypes.ContextKeyTypeEnumIp,
				ContextKeyValues: []string{parsed.SourceIP},
			})
		}
		if parsed.VPCEndpointID != "" {
			contextEntries = append(contextEntries, iamtypes.ContextEntry{
				ContextKeyName:   aws.String("aws:SourceVpce"),
				ContextKeyType:   iamtypes.ContextKeyTypeEnumString,
				ContextKeyValues: []string{parsed.VPCEndpointID},
			})
		}
		if parsed.SessionContext != nil && parsed.SessionContext["mfaAuthenticated"] != "" {
			contextEntries = append(contextEntries, iamtypes.ContextEntry{
				ContextKeyName:   aws.String("aws:MultiFactorAuthPresent"),
				ContextKeyType:   iamtypes.ContextKeyTypeEnumBoolean,
				ContextKeyValues: []string{parsed.SessionContext["mfaAuthenticated"]},
			})
		}

		simResult, err := client.Simulate(ctx, parsed.Principal, parsed.Action, parsed.Resource, contextEntries)
		if err != nil {
			result.Warnings = append(result.Warnings,
				"Simulation failed: "+err.Error()+". Ensure your AWS credentials have iam:SimulatePrincipalPolicy permission.")
		} else {
			result.SimulationRan = true
			result.SimulationResult = simResult.Decision

			switch simResult.Decision {
			case "explicitDeny", "implicitDeny":
				result.SimulationConfirms = true
			case "allowed":
				result.SimulationContradicts = true
				result.Warnings = append(result.Warnings,
					"Simulation says this action should be allowed. The deny may be from a VPC endpoint policy, session policy, or runtime context not captured by simulation.")
			}
		}
	}

	return result
}

// findClosestPolicy fetches each attached policy and finds the one closest to granting the action.
func findClosestPolicy(ctx context.Context, client *Client, policyARNs []string, action, resource string) (*internal.PolicySuggestion, error) {
	var best *internal.PolicySuggestion
	var bestScore int

	for _, arn := range policyARNs {
		_, statements, err := client.FetchPolicy(ctx, arn)
		if err != nil {
			continue // skip policies we can't fetch
		}

		score, reason := scorePolicyRelevance(statements, action, resource)
		if score > bestScore {
			bestScore = score
			// Extract policy name from ARN (last segment after /)
			name := arn
			if idx := strings.LastIndex(arn, "/"); idx >= 0 {
				name = arn[idx+1:]
			}
			best = &internal.PolicySuggestion{
				PolicyARN:  arn,
				PolicyName: name,
				Reason:     reason,
			}
		}
	}
	return best, nil
}

// scorePolicyRelevance scores how close a policy is to granting the denied action.
// Higher score = more relevant (closer to granting).
func scorePolicyRelevance(statements []internal.PolicyStatement, action, resource string) (int, string) {
	score := 0
	reason := ""

	actionService := ""
	if parts := strings.SplitN(action, ":", 2); len(parts) == 2 {
		actionService = parts[0]
	}

	for _, stmt := range statements {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}

		// Check if any action in this statement matches or is close
		for _, a := range stmt.Actions {
			if matchActionPattern(a, action) {
				// Exact action match — check resource
				for _, r := range stmt.Resources {
					if matchResourcePattern(r, resource) {
						// Full match — this policy should allow it (maybe conditions block it)
						return 100, fmt.Sprintf("allows %s on %s (check conditions)", action, r)
					}
					if r == "*" {
						return 100, fmt.Sprintf("allows %s on * (check conditions)", action)
					}
				}
				// Action matches but resource doesn't
				if len(stmt.Resources) > 0 {
					if score < 80 {
						score = 80
						reason = fmt.Sprintf("allows %s on %s — extend Resource to include your target", action, strings.Join(stmt.Resources, ", "))
					}
				}
			}

			// Same service, different action
			aService := ""
			if parts := strings.SplitN(a, ":", 2); len(parts) == 2 {
				aService = strings.ToLower(parts[0])
			}
			if aService == strings.ToLower(actionService) && score < 50 {
				score = 50
				reason = fmt.Sprintf("allows other %s actions (%s) — add %s to the Action list", actionService, a, action)
			}
		}

		// Wildcard actions
		for _, a := range stmt.Actions {
			if a == "*" && score < 90 {
				score = 90
				reason = "allows all actions (check conditions or resource scope)"
			}
		}
	}

	return score, reason
}

// extractRoleNameFromARN extracts the IAM role name from an ARN.
// Handles both arn:aws:iam::123:role/RoleName and arn:aws:sts::123:assumed-role/RoleName/session.
func extractRoleNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	resource := parts[5]
	if strings.HasPrefix(resource, "role/") {
		return strings.TrimPrefix(resource, "role/")
	}
	if strings.HasPrefix(resource, "assumed-role/") {
		segments := strings.SplitN(resource, "/", 3)
		if len(segments) >= 2 {
			return segments[1]
		}
	}
	return ""
}
