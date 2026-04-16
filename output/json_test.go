package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/leredteam/awsdeny/internal"
)

func TestJSONOutput(t *testing.T) {
	result := internal.AnalysisResult{
		Parsed: internal.ParsedError{
			Action:    "s3:GetObject",
			Resource:  "arn:aws:s3:::bucket/key",
			Principal: "arn:aws:iam::123:role/MyRole",
		},
		Explanation: internal.Explanation{
			Summary:          "Blocked by SCP",
			DenyType:         "explicit",
			SourceType:       "scp",
			Reason:           "SCP denies this action",
			Confidence:       "high",
			ConfidenceReason: "heuristic match",
			Level:            1,
			HeuristicID:      "SCP-001",
			Suggestions: []internal.Suggestion{
				{Action: "Contact admin", Difficulty: "medium", Requires: "org admin"},
			},
		},
	}

	var buf bytes.Buffer
	err := JSON(&buf, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed["status"] != "denied" {
		t.Errorf("expected status=denied, got %v", parsed["status"])
	}
	if parsed["action"] != "s3:GetObject" {
		t.Errorf("expected action=s3:GetObject, got %v", parsed["action"])
	}
	if parsed["confidence"] != "high" {
		t.Errorf("expected confidence=high, got %v", parsed["confidence"])
	}
}

func TestJSONOutput_EmptyWarnings(t *testing.T) {
	result := internal.AnalysisResult{
		Parsed:      internal.ParsedError{},
		Explanation: internal.Explanation{},
	}

	var buf bytes.Buffer
	err := JSON(&buf, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify warnings field is omitted when empty
	var parsed map[string]interface{}
	json.Unmarshal(buf.Bytes(), &parsed)
	if _, exists := parsed["warnings"]; exists {
		t.Error("warnings should be omitted when empty")
	}
}
