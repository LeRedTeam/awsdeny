package heuristic

import (
	"sort"

	"github.com/leredteam/awsdeny/internal"
)

// Heuristic defines a pattern that can match and explain an AccessDenied error.
type Heuristic struct {
	ID              string
	Name            string
	Category        string // "scp", "boundary", "condition", "cross-account", "resource-policy", "identity", "network", "session", "common"
	ConfidenceBoost float64
	Match           func(internal.ParsedError) bool
	Explain         func(internal.ParsedError) internal.Explanation
}

type heuristicMatch struct {
	heuristic    *Heuristic
	explanation  internal.Explanation
	catalogIndex int // position in catalog for stable sort tiebreaking
}

// Analyze runs all heuristics against the parsed error and returns the best explanation.
func Analyze(parsed internal.ParsedError) internal.Explanation {
	var matches []heuristicMatch

	for i := range catalog {
		h := &catalog[i]
		if h.Match(parsed) {
			expl := h.Explain(parsed)
			expl.HeuristicID = h.ID
			expl.Level = 1
			matches = append(matches, heuristicMatch{
				heuristic:    h,
				explanation:  expl,
				catalogIndex: i,
			})
		}
	}

	if len(matches) == 0 {
		return defaultExplanation(parsed)
	}

	// Sort by confidence boost (highest first), catalog order as tiebreaker (lower = more specific)
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].heuristic.ConfidenceBoost != matches[j].heuristic.ConfidenceBoost {
			return matches[i].heuristic.ConfidenceBoost > matches[j].heuristic.ConfidenceBoost
		}
		return matches[i].catalogIndex < matches[j].catalogIndex
	})

	best := matches[0]
	conf, confReason := CalculateConfidence(parsed, best.heuristic.ConfidenceBoost, nil)
	best.explanation.Confidence = conf
	best.explanation.ConfidenceReason = confReason
	return best.explanation
}

// AnalyzeWithEnrichment runs heuristics with enrichment data available.
func AnalyzeWithEnrichment(parsed internal.ParsedError, enrichment *internal.EnrichmentResult) internal.Explanation {
	expl := Analyze(parsed)
	if enrichment == nil {
		return expl
	}

	// Recalculate confidence with enrichment data
	boost := 0.0
	for _, h := range catalog {
		if h.ID == expl.HeuristicID {
			boost = h.ConfidenceBoost
			break
		}
	}
	conf, confReason := CalculateConfidence(parsed, boost, enrichment)
	expl.Confidence = conf
	expl.ConfidenceReason = confReason

	// Update level based on enrichment
	if enrichment.SimulationRan {
		expl.Level = 3
	} else if enrichment.PolicyFetched {
		expl.Level = 2
	}

	// Add enrichment warnings
	expl.Warnings = append(expl.Warnings, enrichment.Warnings...)

	return expl
}

func defaultExplanation(parsed internal.ParsedError) internal.Explanation {
	summary := "Access denied"
	reason := "Could not determine the specific cause from the error message."
	denyType := parsed.DenyType
	sourceType := parsed.PolicyType

	if parsed.Action != "" {
		summary = "Access denied for " + parsed.Action
	}
	if denyType == "" {
		denyType = "unknown"
	}
	if sourceType == "" {
		sourceType = "unknown"
	}

	if parsed.Reason != "" {
		reason = parsed.Reason
	}

	suggestions := []internal.Suggestion{
		{
			Action:     "Check your IAM role/user policies for the required permission",
			Difficulty: "easy",
		},
		{
			Action:     "Use --enrich flag with AWS credentials for deeper analysis",
			Difficulty: "easy",
		},
	}

	conf, confReason := CalculateConfidence(parsed, 0, nil)

	return internal.Explanation{
		Summary:          summary,
		DenyType:         denyType,
		SourceType:       sourceType,
		SourceARN:        parsed.PolicyARN,
		Reason:           reason,
		Suggestions:      suggestions,
		Confidence:       conf,
		ConfidenceReason: confReason,
		Level:            1,
	}
}
