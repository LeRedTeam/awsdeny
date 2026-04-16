package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leredteam/awsdeny/enrich"
	"github.com/leredteam/awsdeny/heuristic"
	"github.com/leredteam/awsdeny/internal"
	"github.com/leredteam/awsdeny/license"
	"github.com/leredteam/awsdeny/output"
	"github.com/leredteam/awsdeny/parse"
)

var (
	errorMsg       string
	useStdin       bool
	cloudtrailPath string
	doEnrich       bool
	awsProfile     string
	awsRegion      string
	formatFlag     string
)

var explainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Explain an AWS AccessDenied error",
	Long: `Explain an AWS AccessDenied error with actionable fix suggestions.

Provide the error via --error flag, --stdin, or --cloudtrail for CloudTrail events.
Use --enrich to enable AWS API calls for deeper analysis (requires credentials).`,
	RunE: runExplain,
}

func init() {
	explainCmd.Flags().StringVarP(&errorMsg, "error", "e", "", "AccessDenied error message to explain")
	explainCmd.Flags().BoolVar(&useStdin, "stdin", false, "Read error from stdin")
	explainCmd.Flags().StringVar(&cloudtrailPath, "cloudtrail", "", "Path to CloudTrail event JSON file or directory")
	explainCmd.Flags().BoolVar(&doEnrich, "enrich", false, "Enable AWS API enrichment (Level 2-3, requires credentials)")
	explainCmd.Flags().StringVar(&awsProfile, "profile", "", "AWS profile to use for enrichment")
	explainCmd.Flags().StringVar(&awsRegion, "region", "", "AWS region for API calls")
	explainCmd.Flags().StringVarP(&formatFlag, "format", "f", "", "Output format: human (default), json, sarif, github")
}

func runExplain(cmd *cobra.Command, args []string) error {
	// Determine output format
	format := formatFlag
	if format == "" {
		format = os.Getenv("AWSDENY_FORMAT")
	}
	if format == "" {
		format = "human"
	}

	// Check license for Pro features
	licenseKey := os.Getenv("AWSDENY_LICENSE_KEY")
	if doEnrich {
		if err := license.CheckProFeature(licenseKey, "--enrich"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
			fmt.Fprintf(os.Stderr, "Falling back to Level 1 analysis (parse + heuristic only)\n\n")
			doEnrich = false
		}
	}
	if cloudtrailPath != "" {
		if err := license.CheckProFeature(licenseKey, "--cloudtrail"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(int(internal.ExitLicenseError))
		}
	}
	if format == "sarif" {
		if err := license.CheckProFeature(licenseKey, "SARIF output"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(int(internal.ExitLicenseError))
		}
	}

	// Handle CloudTrail input
	if cloudtrailPath != "" {
		return handleCloudTrail(cmd.Context(), cloudtrailPath, format)
	}

	// Get error message
	raw, err := getErrorMessage()
	if err != nil {
		return err
	}

	// Sanitize input
	raw = internal.Sanitize(raw)

	// Parse the error
	parsed := parse.Parse(raw)
	if parsed.Format == "unknown" && parsed.Action == "" && parsed.Principal == "" {
		fmt.Fprintf(os.Stderr, "Could not parse this error format.\n")
		fmt.Fprintf(os.Stderr, "If this is a valid AccessDenied error, please file an issue:\n")
		fmt.Fprintf(os.Stderr, "  https://github.com/leredteam/awsdeny/issues\n")
		os.Exit(int(internal.ExitParseError))
	}

	// Run analysis
	result := analyze(cmd.Context(), parsed)

	// Output
	writeOutput(os.Stdout, result, format)
	return nil
}

func getErrorMessage() (string, error) {
	if useStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			return "", fmt.Errorf("no input received from stdin")
		}
		return msg, nil
	}

	if errorMsg != "" {
		return errorMsg, nil
	}

	// Check if there are remaining args (user might pass error without flag)
	if len(os.Args) > 2 {
		// Join everything after "explain" as the error message
		return strings.Join(os.Args[2:], " "), nil
	}

	return "", fmt.Errorf("provide an error message with --error, --stdin, or --cloudtrail")
}

func analyze(ctx context.Context, parsed internal.ParsedError) internal.AnalysisResult {
	// Level 1: Heuristic analysis
	explanation := heuristic.Analyze(parsed)

	result := internal.AnalysisResult{
		Parsed:      parsed,
		Explanation: explanation,
	}

	// Level 2-3: Enrichment (if requested and licensed)
	if doEnrich {
		client, err := enrich.NewClient(ctx, awsRegion, awsProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not create AWS client: %s\n", err)
			fmt.Fprintf(os.Stderr, "Falling back to Level 1 analysis.\n\n")
			result.Explanation.Warnings = append(result.Explanation.Warnings,
				"Enrichment failed: "+err.Error())
			return result
		}

		enrichResult := enrich.Enrich(ctx, client, parsed)
		result.Enrichment = enrichResult
		result.Explanation = heuristic.AnalyzeWithEnrichment(parsed, enrichResult)
	}

	return result
}

func handleCloudTrail(ctx context.Context, path string, format string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("accessing CloudTrail path: %w", err)
	}

	var parsedErrors []internal.ParsedError
	if info.IsDir() {
		parsedErrors, err = parse.ParseCloudTrailDir(path)
	} else {
		parsedErrors, err = parse.ParseCloudTrailFile(path)
	}
	if err != nil {
		return fmt.Errorf("parsing CloudTrail: %w", err)
	}

	if len(parsedErrors) == 0 {
		fmt.Println("No AccessDenied events found in CloudTrail data.")
		return nil
	}

	for _, parsed := range parsedErrors {
		result := analyze(ctx, parsed)
		writeOutput(os.Stdout, result, format)
	}

	return nil
}

func writeOutput(w io.Writer, result internal.AnalysisResult, format string) {
	switch format {
	case "json":
		if err := output.JSON(w, result); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %s\n", err)
		}
	case "sarif":
		if err := output.SARIF(w, result, version); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing SARIF: %s\n", err)
		}
	case "github":
		output.GitHubComment(w, result)
	default:
		output.Human(w, result)
	}
}
