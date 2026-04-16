package output

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/leredteam/awsdeny/internal"
)

func capitalize(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// Human writes a human-readable explanation to the writer.
func Human(w io.Writer, result internal.AnalysisResult) {
	p := result.Parsed
	e := result.Explanation

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Access Denied")
	fmt.Fprintln(w)

	if p.Action != "" {
		fmt.Fprintf(w, "  Action:    %s\n", p.Action)
	}
	if p.Resource != "" {
		fmt.Fprintf(w, "  Resource:  %s\n", p.Resource)
	}
	if p.Principal != "" {
		fmt.Fprintf(w, "  Principal: %s\n", p.Principal)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Analysis:")

	if e.DenyType != "" && e.DenyType != "unknown" {
		fmt.Fprintf(w, "    Type:   %s deny\n", capitalize(e.DenyType))
	}

	sourceStr := formatSource(e)
	if sourceStr != "" {
		fmt.Fprintf(w, "    Source: %s\n", sourceStr)
	}

	if e.Reason != "" {
		// Wrap reason text
		lines := wrapText(e.Reason, 70)
		fmt.Fprintf(w, "    Reason: %s\n", lines[0])
		for _, line := range lines[1:] {
			fmt.Fprintf(w, "            %s\n", line)
		}
	}

	if len(e.Suggestions) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Suggested fixes:")
		for i, s := range e.Suggestions {
			prefix := fmt.Sprintf("    %d. ", i+1)
			lines := wrapText(s.Action, 70)
			fmt.Fprintf(w, "%s%s\n", prefix, lines[0])
			indent := strings.Repeat(" ", len(prefix))
			for _, line := range lines[1:] {
				fmt.Fprintf(w, "%s%s\n", indent, line)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Confidence: %s", e.Confidence)
	if e.ConfidenceReason != "" {
		fmt.Fprintf(w, " (%s)", e.ConfidenceReason)
	}
	fmt.Fprintln(w)

	if len(e.Warnings) > 0 {
		fmt.Fprintln(w)
		for _, warn := range e.Warnings {
			fmt.Fprintf(w, "  Warning: %s\n", warn)
		}
	}

	fmt.Fprintln(w)
}

func formatSource(e internal.Explanation) string {
	if e.SourceType == "" || e.SourceType == "unknown" {
		if e.SourceARN != "" {
			return e.SourceARN
		}
		return ""
	}
	name := sourceTypeLabel(e.SourceType)
	if e.SourceARN != "" {
		return fmt.Sprintf("%s (%s)", name, e.SourceARN)
	}
	return name
}

func sourceTypeLabel(st string) string {
	switch st {
	case "scp":
		return "Service Control Policy (SCP)"
	case "identity":
		return "Identity-based policy"
	case "resource":
		return "Resource-based policy"
	case "boundary":
		return "Permissions boundary"
	case "session":
		return "Session policy"
	case "vpce":
		return "VPC endpoint policy"
	case "cross-account":
		return "Cross-account access"
	default:
		return st
	}
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	current := ""

	for _, word := range words {
		if current == "" {
			current = word
		} else if len(current)+1+len(word) <= width {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	if current != "" {
		lines = append(lines, current)
	}

	if len(lines) == 0 {
		return []string{text}
	}
	return lines
}
