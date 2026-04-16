package parse

import (
	"testing"
)

func TestParseCloudTrailJSON_SingleEvent(t *testing.T) {
	data := []byte(`{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "AssumedRole",
			"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
			"accountId": "123456789012",
			"sessionContext": {
				"attributes": {"mfaAuthenticated": "false"},
				"sessionIssuer": {
					"type": "Role",
					"arn": "arn:aws:iam::123456789012:role/MyRole",
					"accountId": "123456789012",
					"userName": "MyRole"
				}
			}
		},
		"eventTime": "2024-01-15T10:05:00Z",
		"eventSource": "s3.amazonaws.com",
		"eventName": "GetObject",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "10.0.1.50",
		"userAgent": "aws-cli/2.13.0",
		"errorCode": "AccessDenied",
		"errorMessage": "Access Denied",
		"requestParameters": {
			"bucketName": "my-bucket",
			"key": "data.csv"
		},
		"resources": [
			{
				"accountId": "123456789012",
				"type": "AWS::S3::Object",
				"ARN": "arn:aws:s3:::my-bucket/data.csv"
			}
		],
		"vpcEndpointId": "vpce-abc123"
	}`)

	results, err := ParseCloudTrailJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	p := results[0]
	assertEqual(t, "cloudtrail", p.Format)
	assertEqual(t, "arn:aws:iam::123456789012:role/MyRole", p.Principal)
	assertEqual(t, "s3:GetObject", p.Action)
	assertEqual(t, "arn:aws:s3:::my-bucket/data.csv", p.Resource)
	assertEqual(t, "us-east-1", p.Region)
	assertEqual(t, "10.0.1.50", p.SourceIP)
	assertEqual(t, "vpce-abc123", p.VPCEndpointID)
	assertEqual(t, "123456789012", p.AccountID)

	if p.ParseLevel != 4 {
		t.Errorf("expected parse level 4, got %d", p.ParseLevel)
	}
}

func TestParseCloudTrailJSON_Records(t *testing.T) {
	data := []byte(`{
		"Records": [
			{
				"eventSource": "s3.amazonaws.com",
				"eventName": "GetObject",
				"errorCode": "AccessDenied",
				"errorMessage": "Access Denied",
				"userIdentity": {"arn": "arn:aws:iam::123:user/dev", "accountId": "123"},
				"requestParameters": {"bucketName": "bucket", "key": "file.txt"}
			},
			{
				"eventSource": "s3.amazonaws.com",
				"eventName": "PutObject",
				"errorCode": "",
				"userIdentity": {"arn": "arn:aws:iam::123:user/dev", "accountId": "123"}
			}
		]
	}`)

	results, err := ParseCloudTrailJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the AccessDenied event should be returned
	if len(results) != 1 {
		t.Fatalf("expected 1 result (only denied events), got %d", len(results))
	}

	assertEqual(t, "s3:GetObject", results[0].Action)
}

func TestParseCloudTrailJSON_NonAccessDenied(t *testing.T) {
	data := []byte(`{
		"eventSource": "s3.amazonaws.com",
		"eventName": "GetObject",
		"errorCode": "NoSuchBucket",
		"userIdentity": {"arn": "arn:aws:iam::123:user/dev", "accountId": "123"}
	}`)

	results, err := ParseCloudTrailJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for non-AccessDenied event, got %d", len(results))
	}
}

func TestParseCloudTrailJSON_InferResource(t *testing.T) {
	data := []byte(`{
		"eventSource": "s3.amazonaws.com",
		"eventName": "GetObject",
		"errorCode": "AccessDenied",
		"errorMessage": "Access Denied",
		"userIdentity": {"arn": "arn:aws:iam::123:user/dev", "accountId": "123"},
		"requestParameters": {"bucketName": "my-bucket", "key": "path/file.txt"}
	}`)

	results, err := ParseCloudTrailJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	assertEqual(t, "arn:aws:s3:::my-bucket/path/file.txt", results[0].Resource)
}

func TestParseCloudTrailJSON_ArbitraryJSON(t *testing.T) {
	data := []byte(`{"foo": "bar", "baz": 123}`)

	_, err := ParseCloudTrailJSON(data)
	if err == nil {
		t.Error("expected error for non-CloudTrail JSON")
	}
}

func TestParseCloudTrailJSON_InvalidJSON(t *testing.T) {
	data := []byte(`not json`)

	_, err := ParseCloudTrailJSON(data)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
