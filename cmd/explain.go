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
	Args: cobra.ArbitraryArgs,
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
	enrichActive := doEnrich
	licenseKey := os.Getenv("AWSDENY_LICENSE_KEY")
	if enrichActive {
		result := license.CheckProFeature(licenseKey, "--enrich")
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", result.Err)
			fmt.Fprintf(os.Stderr, "Falling back to Level 1 analysis (parse + heuristic only)\n\n")
			enrichActive = false
		} else if result.Warning != "" {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", result.Warning)
		}
	}
	if cloudtrailPath != "" {
		result := license.CheckProFeature(licenseKey, "--cloudtrail")
		if result.Err != nil {
			return internal.NewExitError(internal.ExitLicenseError, result.Err.Error())
		}
		if result.Warning != "" {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", result.Warning)
		}
	}
	if format == "sarif" {
		result := license.CheckProFeature(licenseKey, "SARIF output")
		if result.Err != nil {
			return internal.NewExitError(internal.ExitLicenseError, result.Err.Error())
		}
		if result.Warning != "" {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", result.Warning)
		}
	}

	// Handle CloudTrail input
	if cloudtrailPath != "" {
		return handleCloudTrail(cmd.Context(), cloudtrailPath, format, enrichActive)
	}

	// Get error message
	raw, err := getErrorMessage(args)
	if err != nil {
		return err
	}

	// Sanitize input
	raw = internal.Sanitize(raw)

	// Parse the error
	parsed := parse.Parse(raw)
	if parsed.Format == "unknown" && parsed.Action == "" && parsed.Principal == "" {
		return internal.NewExitError(internal.ExitParseError,
			"Could not parse this error format.\nIf this is a valid AccessDenied error, please file an issue:\n  https://github.com/leredteam/awsdeny/issues")
	}

	// Run analysis
	result := analyzeError(cmd.Context(), parsed, enrichActive)

	// Output
	if err := writeOutput(os.Stdout, result, format); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func getErrorMessage(args []string) (string, error) {
	if useStdin {
		const maxStdinBytes = 1 << 20 // 1MB
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinBytes))
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

	// Use positional args from cobra if provided
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}

	return "", fmt.Errorf("provide an error message with --error, --stdin, or --cloudtrail")
}

func analyzeError(ctx context.Context, parsed internal.ParsedError, enrichActive bool) internal.AnalysisResult {
	// Level 1: Heuristic analysis
	explanation := heuristic.Analyze(parsed)

	result := internal.AnalysisResult{
		Parsed:      parsed,
		Explanation: explanation,
	}

	// Level 2-3: Enrichment (if requested and licensed)
	if enrichActive {
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

func handleCloudTrail(ctx context.Context, path string, format string, enrichActive bool) error {
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
		return internal.NewExitError(internal.ExitParseError, fmt.Sprintf("parsing CloudTrail: %s", err))
	}

	if len(parsedErrors) == 0 {
		fmt.Fprintln(os.Stderr, "No AccessDenied events found in CloudTrail data.")
		return nil
	}

	var results []internal.AnalysisResult
	for _, parsed := range parsedErrors {
		results = append(results, analyzeError(ctx, parsed, enrichActive))
	}

	if err := writeMultiOutput(os.Stdout, results, format); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func writeOutput(w io.Writer, result internal.AnalysisResult, format string) error {
	switch format {
	case "json":
		return output.JSON(w, result)
	case "sarif":
		return output.SARIF(w, result, version)
	case "github":
		output.GitHubComment(w, result)
	default:
		output.Human(w, result)
	}
	return nil
}

func writeMultiOutput(w io.Writer, results []internal.AnalysisResult, format string) error {
	switch format {
	case "json":
		return output.JSONArray(w, results)
	case "sarif":
		return output.SARIFMulti(w, results, version)
	default:
		for i, result := range results {
			if i > 0 {
				switch format {
				case "github":
					fmt.Fprintln(w, "---")
				default:
					fmt.Fprintln(w)
				}
			}
			if err := writeOutput(w, result, format); err != nil {
				return err
			}
		}
	}
	return nil
}
