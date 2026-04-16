package enrich

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DecodeAuthorizationMessage decodes an EC2 encoded authorization failure message.
func (c *Client) DecodeAuthorizationMessage(ctx context.Context, encodedMessage string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out, err := c.STS.DecodeAuthorizationMessage(ctx, &sts.DecodeAuthorizationMessageInput{
		EncodedMessage: aws.String(encodedMessage),
	})
	if err != nil {
		return "", fmt.Errorf("sts:DecodeAuthorizationMessage: %w", err)
	}

	return aws.ToString(out.DecodedMessage), nil
}
