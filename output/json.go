package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/leredteam/awsdeny/internal"
)

type jsonOutput struct {
	Status           string           `json:"status"`
	Action           string           `json:"action,omitempty"`
	Resource         string           `json:"resource,omitempty"`
	Principal        string           `json:"principal,omitempty"`
	Analysis         jsonAnalysis     `json:"analysis"`
	Suggestions      []jsonSuggestion `json:"suggestions"`
	Confidence       string           `json:"confidence"`
	ConfidenceReason string           `json:"confidence_reason"`
	Level            int              `json:"level"`
	Warnings         []string         `json:"warnings,omitempty"`
}

type jsonAnalysis struct {
	DenyType         string `json:"deny_type"`
	SourceType       string `json:"source_type"`
	SourceARN        string `json:"source_arn,omitempty"`
	Reason           string `json:"reason"`
	MatchedHeuristic string `json:"matched_heuristic,omitempty"`
}

type jsonSuggestion struct {
	Action     string `json:"action"`
	Difficulty string `json:"difficulty"`
	Requires   string `json:"requires,omitempty"`
}

// JSON writes a JSON-formatted explanation to the writer.
func JSON(w io.Writer, result internal.AnalysisResult) error {
	p := result.Parsed
	e := result.Explanation

	suggestions := make([]jsonSuggestion, len(e.Suggestions))
	for i, s := range e.Suggestions {
		suggestions[i] = jsonSuggestion{
			Action:     s.Action,
			Difficulty: s.Difficulty,
			Requires:   s.Requires,
		}
	}

	out := jsonOutput{
		Status:    "denied",
		Action:    p.Action,
		Resource:  p.Resource,
		Principal: p.Principal,
		Analysis: jsonAnalysis{
			DenyType:         e.DenyType,
			SourceType:       e.SourceType,
			SourceARN:        e.SourceARN,
			Reason:           e.Reason,
			MatchedHeuristic: e.HeuristicID,
		},
		Suggestions:      suggestions,
		Confidence:       e.Confidence,
		ConfidenceReason: e.ConfidenceReason,
		Level:            e.Level,
		Warnings:         e.Warnings,
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}

// JSONArray writes multiple results as a valid JSON array.
func JSONArray(w io.Writer, results []internal.AnalysisResult) error {
	items := make([]jsonOutput, 0, len(results))
	for _, result := range results {
		p := result.Parsed
		e := result.Explanation

		suggestions := make([]jsonSuggestion, len(e.Suggestions))
		for i, s := range e.Suggestions {
			suggestions[i] = jsonSuggestion{
				Action:     s.Action,
				Difficulty: s.Difficulty,
				Requires:   s.Requires,
			}
		}

		items = append(items, jsonOutput{
			Status:    "denied",
			Action:    p.Action,
			Resource:  p.Resource,
			Principal: p.Principal,
			Analysis: jsonAnalysis{
				DenyType:         e.DenyType,
				SourceType:       e.SourceType,
				SourceARN:        e.SourceARN,
				Reason:           e.Reason,
				MatchedHeuristic: e.HeuristicID,
			},
			Suggestions:      suggestions,
			Confidence:       e.Confidence,
			ConfidenceReason: e.ConfidenceReason,
			Level:            e.Level,
			Warnings:         e.Warnings,
		})
	}

	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON array: %w", err)
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}
