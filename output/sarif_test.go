package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/leredteam/awsdeny/internal"
)

func TestSARIFOutput_ValidJSON(t *testing.T) {
	result := internal.AnalysisResult{
		Parsed: internal.ParsedError{
			Action:    "s3:GetObject",
			Resource:  "arn:aws:s3:::bucket/key",
			Principal: "arn:aws:iam::123:role/MyRole",
		},
		Explanation: internal.Explanation{
			Summary:     "Blocked by SCP",
			DenyType:    "explicit",
			SourceType:  "scp",
			Reason:      "SCP denies this action",
			Confidence:  "high",
			Level:       1,
			HeuristicID: "SCP-001",
			Suggestions: []internal.Suggestion{
				{Action: "Contact admin", Difficulty: "medium"},
			},
		},
	}

	var buf bytes.Buffer
	err := SARIF(&buf, result, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check SARIF schema version
	if parsed["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", parsed["version"])
	}

	// Check runs exist
	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Error("expected non-empty runs array")
	}
}

func TestSARIFOutput_EmptyHeuristicID(t *testing.T) {
	result := internal.AnalysisResult{
		Parsed:      internal.ParsedError{},
		Explanation: internal.Explanation{HeuristicID: ""},
	}

	var buf bytes.Buffer
	err := SARIF(&buf, result, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should default to "awsdeny/unknown"
	var parsed map[string]interface{}
	json.Unmarshal(buf.Bytes(), &parsed)
	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	r := results[0].(map[string]interface{})
	if r["ruleId"] != "awsdeny/unknown" {
		t.Errorf("expected ruleId=awsdeny/unknown, got %v", r["ruleId"])
	}
}
