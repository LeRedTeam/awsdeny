package enrich

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// SimulateResult holds the result of a SimulatePrincipalPolicy call.
type SimulateResult struct {
	Decision          string // "allowed", "implicitDeny", "explicitDeny"
	MatchedStatements []string
	MissingContext    []string
}

// Simulate runs iam:SimulatePrincipalPolicy for the given parameters.
func (c *Client) Simulate(ctx context.Context, principal, action, resource string, contextEntries []iamtypes.ContextEntry) (*SimulateResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// SimulatePrincipalPolicy requires an IAM ARN, not an STS assumed-role ARN.
	// Convert arn:aws:sts::ACCT:assumed-role/ROLE/SESSION -> arn:aws:iam::ACCT:role/ROLE
	simulationArn := normalizeToIAMArn(principal)

	input := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(simulationArn),
		ActionNames:     []string{action},
	}

	if resource != "" {
		input.ResourceArns = []string{resource}
	}

	if len(contextEntries) > 0 {
		input.ContextEntries = contextEntries
	}

	out, err := c.IAM.SimulatePrincipalPolicy(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("iam:SimulatePrincipalPolicy: %w", err)
	}

	if len(out.EvaluationResults) == 0 {
		return nil, fmt.Errorf("no evaluation results returned")
	}

	result := &SimulateResult{}
	eval := out.EvaluationResults[0]

	switch eval.EvalDecision {
	case iamtypes.PolicyEvaluationDecisionTypeAllowed:
		result.Decision = "allowed"
	case iamtypes.PolicyEvaluationDecisionTypeImplicitDeny:
		result.Decision = "implicitDeny"
	case iamtypes.PolicyEvaluationDecisionTypeExplicitDeny:
		result.Decision = "explicitDeny"
	default:
		result.Decision = string(eval.EvalDecision)
	}

	for _, stmt := range eval.MatchedStatements {
		result.MatchedStatements = append(result.MatchedStatements,
			aws.ToString(stmt.SourcePolicyId))
	}

	result.MissingContext = eval.MissingContextValues

	return result, nil
}

// normalizeToIAMArn converts STS assumed-role ARNs to IAM role ARNs.
// arn:aws:sts::123:assumed-role/MyRole/session -> arn:aws:iam::123:role/MyRole
// Other ARN formats are returned as-is.
func normalizeToIAMArn(arn string) string {
	if !strings.Contains(arn, ":assumed-role/") {
		return arn
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	// parts[2] is "sts", parts[5] is "assumed-role/ROLE/SESSION"
	resource := parts[5]
	segments := strings.SplitN(resource, "/", 3)
	if len(segments) < 2 || segments[0] != "assumed-role" {
		return arn
	}
	roleName := segments[1]
	parts[2] = "iam"
	parts[5] = "role/" + roleName
	return strings.Join(parts, ":")
}
