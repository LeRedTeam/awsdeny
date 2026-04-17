package enrich

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// IAMAPI abstracts IAM API calls for testing.
type IAMAPI interface {
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

// OrgsAPI abstracts Organizations API calls for testing.
type OrgsAPI interface {
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

// STSAPI abstracts STS API calls for testing.
type STSAPI interface {
	DecodeAuthorizationMessage(ctx context.Context, params *sts.DecodeAuthorizationMessageInput, optFns ...func(*sts.Options)) (*sts.DecodeAuthorizationMessageOutput, error)
}

// Client wraps AWS service clients for enrichment.
type Client struct {
	IAM  IAMAPI
	Orgs OrgsAPI
	STS  STSAPI
	cfg  aws.Config
}

// NewClient creates a new enrichment client using the default credential chain.
func NewClient(ctx context.Context, region, profile string) (*Client, error) {
	opts := []func(*config.LoadOptions) error{}

	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return &Client{
		IAM:  iam.NewFromConfig(cfg),
		Orgs: organizations.NewFromConfig(cfg),
		STS:  sts.NewFromConfig(cfg),
		cfg:  cfg,
	}, nil
}

// ListAttachedRolePolicies returns the policy ARNs attached to the given IAM role.
func (c *Client) ListAttachedRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out, err := c.IAM.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("iam:ListAttachedRolePolicies: %w", err)
	}

	var arns []string
	for _, p := range out.AttachedPolicies {
		arns = append(arns, aws.ToString(p.PolicyArn))
	}
	return arns, nil
}
