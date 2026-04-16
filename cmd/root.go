package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time via ldflags.
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "awsdeny",
	Short: "AWS AccessDenied Explainer",
	Long: `awsdeny explains AWS AccessDenied errors with actionable fix suggestions.

Paste an AccessDenied error and get a clear explanation of what went wrong,
why it happened, and how to fix it.

Examples:
  awsdeny explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::my-bucket/key"
  echo "<error>" | awsdeny explain --stdin
  awsdeny explain --error "<error>" --enrich --profile my-profile
  awsdeny explain --cloudtrail event.json`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(licenseCmd)
}
