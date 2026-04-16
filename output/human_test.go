package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leredteam/awsdeny/internal"
)

func TestHumanOutput_ContainsAllFields(t *testing.T) {
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
			Suggestions: []internal.Suggestion{
				{Action: "Contact admin", Difficulty: "medium"},
			},
		},
	}

	var buf bytes.Buffer
	Human(&buf, result)
	out := buf.String()

	expectations := []string{
		"Access Denied",
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
		"arn:aws:iam::123:role/MyRole",
		"Explicit deny",
		"Service Control Policy (SCP)",
		"SCP denies this action",
		"Contact admin",
		"high",
		"heuristic match",
	}

	for _, exp := range expectations {
		if !strings.Contains(out, exp) {
			t.Errorf("output missing expected string: %q", exp)
		}
	}
}

func TestHumanOutput_WithWarnings(t *testing.T) {
	result := internal.AnalysisResult{
		Parsed:      internal.ParsedError{Action: "s3:GetObject"},
		Explanation: internal.Explanation{
			Summary:    "Test",
			DenyType:   "unknown",
			SourceType: "unknown",
			Confidence: "low",
			Warnings:   []string{"Enrichment failed: access denied"},
		},
	}

	var buf bytes.Buffer
	Human(&buf, result)
	out := buf.String()

	if !strings.Contains(out, "Warning: Enrichment failed") {
		t.Error("output missing warning")
	}
}
