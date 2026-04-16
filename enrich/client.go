package enrich

import (
	"context"
	"fmt"

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
