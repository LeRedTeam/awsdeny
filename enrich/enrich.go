package enrich

import (
	"context"

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

	// Level 2.5: Decode EC2 encoded message
	if parsed.EncodedMessage != "" {
		decoded, err := client.DecodeAuthorizationMessage(ctx, parsed.EncodedMessage)
		if err != nil {
			result.Warnings = append(result.Warnings,
				"Could not decode EC2 authorization message: "+err.Error())
		} else {
			result.DecodedMessage = decoded
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
