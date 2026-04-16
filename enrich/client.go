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

// Client wraps AWS service clients for enrichment.
type Client struct {
	IAM  *iam.Client
	Orgs *organizations.Client
	STS  *sts.Client
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
