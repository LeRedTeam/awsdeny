package enrich

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"github.com/leredteam/awsdeny/internal"
)

// FetchPolicy fetches the policy document for the given ARN.
func (c *Client) FetchPolicy(ctx context.Context, policyARN string) (string, []internal.PolicyStatement, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if strings.Contains(policyARN, ":policy/o-") || strings.Contains(policyARN, "organizations::") {
		return c.fetchSCPPolicy(ctx, policyARN)
	}

	return c.fetchIAMPolicy(ctx, policyARN)
}

func (c *Client) fetchIAMPolicy(ctx context.Context, policyARN string) (string, []internal.PolicyStatement, error) {
	// Get policy metadata
	policyOut, err := c.IAM.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyARN),
	})
	if err != nil {
		return "", nil, fmt.Errorf("iam:GetPolicy: %w", err)
	}

	// Get the actual document
	versionOut, err := c.IAM.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: policyOut.Policy.DefaultVersionId,
	})
	if err != nil {
		return "", nil, fmt.Errorf("iam:GetPolicyVersion: %w", err)
	}

	// URL-decode the document
	document, err := url.QueryUnescape(aws.ToString(versionOut.PolicyVersion.Document))
	if err != nil {
		return "", nil, fmt.Errorf("decoding policy document: %w", err)
	}

	statements, err := ParsePolicyDocument(document)
	if err != nil {
		return document, nil, fmt.Errorf("parsing policy document: %w", err)
	}

	return document, statements, nil
}

func (c *Client) fetchSCPPolicy(ctx context.Context, policyARN string) (string, []internal.PolicyStatement, error) {
	// Extract policy ID from ARN
	policyID := extractPolicyID(policyARN)
	if policyID == "" {
		return "", nil, fmt.Errorf("could not extract policy ID from ARN: %s", policyARN)
	}

	out, err := c.Orgs.DescribePolicy(ctx, &organizations.DescribePolicyInput{
		PolicyId: aws.String(policyID),
	})
	if err != nil {
		return "", nil, fmt.Errorf("organizations:DescribePolicy: %w", err)
	}

	document := aws.ToString(out.Policy.Content)
	statements, err := ParsePolicyDocument(document)
	if err != nil {
		return document, nil, fmt.Errorf("parsing SCP document: %w", err)
	}

	return document, statements, nil
}

// extractPolicyID extracts the policy ID (e.g., "p-abc123") from an Organizations policy ARN.
func extractPolicyID(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		if strings.HasPrefix(last, "p-") {
			return last
		}
	}
	// Try to find p-xxx pattern anywhere
	for _, part := range parts {
		if strings.HasPrefix(part, "p-") {
			return part
		}
	}
	return ""
}
