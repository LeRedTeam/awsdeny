package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leredteam/awsdeny/internal"
)

// cloudTrailEvent represents the relevant fields from a CloudTrail event JSON.
type cloudTrailEvent struct {
	EventVersion string `json:"eventVersion"`
	UserIdentity struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		ARN         string `json:"arn"`
		AccountID   string `json:"accountId"`
		SessionContext struct {
			Attributes struct {
				MFAAuthenticated string `json:"mfaAuthenticated"`
				CreationDate     string `json:"creationDate"`
			} `json:"attributes"`
			SessionIssuer struct {
				Type        string `json:"type"`
				PrincipalID string `json:"principalId"`
				ARN         string `json:"arn"`
				AccountID   string `json:"accountId"`
				UserName    string `json:"userName"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	EventTime        string                 `json:"eventTime"`
	EventSource      string                 `json:"eventSource"`
	EventName        string                 `json:"eventName"`
	AWSRegion        string                 `json:"awsRegion"`
	SourceIPAddress  string                 `json:"sourceIPAddress"`
	UserAgent        string                 `json:"userAgent"`
	ErrorCode        string                 `json:"errorCode"`
	ErrorMessage     string                 `json:"errorMessage"`
	RequestParameters map[string]interface{} `json:"requestParameters"`
	Resources        []struct {
		AccountID string `json:"accountId"`
		Type      string `json:"type"`
		ARN       string `json:"ARN"`
	} `json:"resources"`
	VPCEndpointID string `json:"vpcEndpointId"`
}

// cloudTrailRecords wraps a CloudTrail log file which may contain multiple events.
type cloudTrailRecords struct {
	Records []cloudTrailEvent `json:"Records"`
}

// ParseCloudTrailFile reads a CloudTrail JSON file and returns parsed errors for denied events.
func ParseCloudTrailFile(path string) ([]internal.ParsedError, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CloudTrail file: %w", err)
	}
	return ParseCloudTrailJSON(data)
}

// ParseCloudTrailDir reads all JSON files in a directory and returns parsed errors.
// Files that fail to parse are reported via warnings on stderr.
func ParseCloudTrailDir(dir string) ([]internal.ParsedError, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	var results []internal.ParsedError
	var skipped int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		parsed, err := ParseCloudTrailFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %s\n", entry.Name(), err)
			skipped++
			continue
		}
		results = append(results, parsed...)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d file(s) skipped due to parse errors\n", skipped)
	}
	return results, nil
}

// ParseCloudTrailJSON parses CloudTrail JSON data (single event or Records array).
func ParseCloudTrailJSON(data []byte) ([]internal.ParsedError, error) {
	// Try as a Records array first
	var records cloudTrailRecords
	if err := json.Unmarshal(data, &records); err == nil && len(records.Records) > 0 {
		return parseCloudTrailEvents(records.Records), nil
	}

	// Try as a single event
	var event cloudTrailEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("invalid CloudTrail JSON: %w", err)
	}

	// Validate it's actually a CloudTrail event, not arbitrary JSON
	if event.EventSource == "" && event.ErrorCode == "" && event.EventName == "" {
		return nil, fmt.Errorf("invalid CloudTrail event: missing eventSource, errorCode, and eventName")
	}

	return parseCloudTrailEvents([]cloudTrailEvent{event}), nil
}

func parseCloudTrailEvents(events []cloudTrailEvent) []internal.ParsedError {
	var results []internal.ParsedError
	for _, event := range events {
		if !isAccessDenied(event) {
			continue
		}
		results = append(results, parseCloudTrailEvent(event))
	}
	return results
}

func isAccessDenied(event cloudTrailEvent) bool {
	code := strings.ToLower(event.ErrorCode)
	return code == "accessdenied" ||
		code == "accessdeniedexception" ||
		code == "unauthorizedaccess" ||
		code == "unauthorizedoperation" ||
		code == "client.unauthorizedaccess" ||
		// Intentional catch-all for service-specific codes like SomeServiceAccessDeniedException
		strings.Contains(code, "accessdenied")
}

func parseCloudTrailEvent(event cloudTrailEvent) internal.ParsedError {
	// Sanitize error message before any parsing to prevent credential leakage
	event.ErrorMessage = internal.Sanitize(event.ErrorMessage)

	parsed := internal.ParsedError{
		RawMessage: event.ErrorMessage,
		Format:     "cloudtrail",
		ParseLevel: 4,
		ErrorCode:  event.ErrorCode,
		EventTime:  event.EventTime,
		Region:     event.AWSRegion,
		SourceIP:   event.SourceIPAddress,
		UserAgent:  event.UserAgent,
		VPCEndpointID: event.VPCEndpointID,
	}

	// Extract principal
	if event.UserIdentity.SessionContext.SessionIssuer.ARN != "" {
		parsed.Principal = event.UserIdentity.SessionContext.SessionIssuer.ARN
	} else if event.UserIdentity.ARN != "" {
		parsed.Principal = event.UserIdentity.ARN
	}

	parsed.AccountID = event.UserIdentity.AccountID

	// Map eventSource + eventName to IAM action
	parsed.Operation = event.EventName
	parsed.Action = mapEventToAction(event.EventSource, event.EventName)

	// Extract resource ARN
	if len(event.Resources) > 0 {
		parsed.Resource = event.Resources[0].ARN
	}

	// Build resource ARN from requestParameters if not in resources
	if parsed.Resource == "" {
		parsed.Resource = inferResourceFromParams(event)
	}

	// Session context
	parsed.SessionContext = map[string]string{
		"mfaAuthenticated": event.UserIdentity.SessionContext.Attributes.MFAAuthenticated,
		"sessionType":      event.UserIdentity.Type,
	}

	// Also parse the error message for additional details
	if event.ErrorMessage != "" {
		msgParsed := Parse(event.ErrorMessage)
		// Merge any additional info from the error message
		if parsed.DenyType == "" && msgParsed.DenyType != "" {
			parsed.DenyType = msgParsed.DenyType
		}
		if parsed.PolicyType == "" && msgParsed.PolicyType != "" {
			parsed.PolicyType = msgParsed.PolicyType
		}
		if parsed.PolicyARN == "" && msgParsed.PolicyARN != "" {
			parsed.PolicyARN = msgParsed.PolicyARN
		}
		if parsed.Reason == "" && msgParsed.Reason != "" {
			parsed.Reason = msgParsed.Reason
		}
	}

	return parsed
}

// mapEventToAction converts CloudTrail eventSource + eventName to IAM action.
func mapEventToAction(eventSource, eventName string) string {
	// First try the operation-to-action map
	if action, ok := operationToAction[eventName]; ok {
		return action
	}

	// Infer from eventSource (e.g., "s3.amazonaws.com" -> "s3")
	service := strings.TrimSuffix(eventSource, ".amazonaws.com")
	if service != "" && eventName != "" {
		return service + ":" + eventName
	}
	return ""
}

// partitionFromRegion infers the AWS partition from the region string.
func partitionFromRegion(region string) string {
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov"
	}
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn"
	}
	return "aws"
}

// inferResourceFromParams tries to build a resource ARN from CloudTrail requestParameters.
func inferResourceFromParams(event cloudTrailEvent) string {
	if event.RequestParameters == nil {
		return ""
	}

	service := strings.TrimSuffix(event.EventSource, ".amazonaws.com")
	partition := partitionFromRegion(event.AWSRegion)

	switch service {
	case "s3":
		bucket, _ := event.RequestParameters["bucketName"].(string)
		key, _ := event.RequestParameters["key"].(string)
		if bucket != "" {
			if key != "" {
				return fmt.Sprintf("arn:%s:s3:::%s/%s", partition, bucket, key)
			}
			return fmt.Sprintf("arn:%s:s3:::%s", partition, bucket)
		}
	case "dynamodb":
		table, _ := event.RequestParameters["tableName"].(string)
		if table != "" && event.AWSRegion != "" && event.UserIdentity.AccountID != "" {
			return fmt.Sprintf("arn:%s:dynamodb:%s:%s:table/%s",
				partition, event.AWSRegion, event.UserIdentity.AccountID, table)
		}
	case "lambda":
		funcName, _ := event.RequestParameters["functionName"].(string)
		if funcName != "" && event.AWSRegion != "" && event.UserIdentity.AccountID != "" {
			return fmt.Sprintf("arn:%s:lambda:%s:%s:function:%s",
				partition, event.AWSRegion, event.UserIdentity.AccountID, funcName)
		}
	}

	return ""
}
