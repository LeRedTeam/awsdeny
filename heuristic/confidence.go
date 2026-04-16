package heuristic

import "github.com/leredteam/awsdeny/internal"

// CalculateConfidence computes the confidence level based on available data.
func CalculateConfidence(parsed internal.ParsedError, heuristicConf float64, enrichment *internal.EnrichmentResult) (string, string) {
	score := 0.0

	// Base: what did we extract from the error?
	if parsed.Action != "" {
		score += 0.2
	}
	if parsed.Resource != "" {
		score += 0.1
	}
	if parsed.Principal != "" {
		score += 0.1
	}
	if parsed.DenyType != "" {
		score += 0.15
	}
	if parsed.PolicyType != "" {
		score += 0.15
	}
	if parsed.PolicyARN != "" {
		score += 0.1
	}

	// Heuristic match confidence boost
	score += heuristicConf

	// Enrichment
	if enrichment != nil {
		if enrichment.PolicyFetched {
			score += 0.2
		}
		if enrichment.SimulationConfirms {
			score += 0.3
		}
		if enrichment.SimulationContradicts {
			score -= 0.2
		}
	}

	// CloudTrail
	if parsed.ParseLevel >= 4 {
		score += 0.2
	}

	// Clamp
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	var level, reason string
	switch {
	case score >= 0.8:
		level = "very-high"
	case score >= 0.6:
		level = "high"
	case score >= 0.4:
		level = "medium"
	default:
		level = "low"
	}

	// Build reason string
	switch {
	case enrichment != nil && enrichment.SimulationConfirms:
		reason = "policy fetched and verified via simulation"
	case enrichment != nil && enrichment.PolicyFetched:
		reason = "policy fetched and analyzed"
	case parsed.ParseLevel >= 4:
		reason = "full context from CloudTrail event"
	case heuristicConf >= 0.2:
		reason = "heuristic match"
	default:
		reason = "based on error pattern only"
	}

	return level, reason
}
