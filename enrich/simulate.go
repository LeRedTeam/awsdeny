package enrich

import (
	"context"
	"fmt"
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
func (c *Client) Simulate(ctx context.Context, principal, action, resource string) (*SimulateResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	input := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principal),
		ActionNames:     []string{action},
	}

	if resource != "" {
		input.ResourceArns = []string{resource}
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
