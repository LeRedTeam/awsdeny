package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/leredteam/awsdeny/internal"
)

// SARIF output structures (Static Analysis Results Interchange Format)
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	Help             sarifMessage    `json:"help"`
	Properties       sarifProperties `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifProperties struct {
	Tags []string `json:"tags,omitempty"`
}

// SARIF writes a SARIF-formatted report to the writer.
func SARIF(w io.Writer, result internal.AnalysisResult, version string) error {
	e := result.Explanation

	ruleID := "awsdeny/" + e.HeuristicID
	if e.HeuristicID == "" {
		ruleID = "awsdeny/unknown"
	}

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "awsdeny",
						Version:        version,
						InformationURI: "https://github.com/leredteam/awsdeny",
						Rules: []sarifRule{
							{
								ID:               ruleID,
								Name:             e.Summary,
								ShortDescription: sarifMessage{Text: e.Summary},
								FullDescription:  sarifMessage{Text: e.Reason},
								Help:             sarifMessage{Text: formatSuggestions(e.Suggestions)},
								Properties:       sarifProperties{Tags: []string{"security", "iam", "aws"}},
							},
						},
					},
				},
				Results: []sarifResult{
					{
						RuleID:  ruleID,
						Level:   "error",
						Message: sarifMessage{Text: e.Reason},
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF: %w", err)
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}

func formatSuggestions(suggestions []internal.Suggestion) string {
	text := "Suggested fixes:\n"
	for i, s := range suggestions {
		text += fmt.Sprintf("%d. %s", i+1, s.Action)
		if s.Requires != "" {
			text += fmt.Sprintf(" (requires: %s)", s.Requires)
		}
		text += "\n"
	}
	return text
}
