package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/leredteam/awsdeny/license"
)

var licenseCmd = &cobra.Command{
	Use:    "license",
	Short:  "License management",
	Hidden: true,
}

var licenseStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show license status",
	RunE: func(cmd *cobra.Command, args []string) error {
		key := os.Getenv("AWSDENY_LICENSE_KEY")
		if key == "" {
			fmt.Println("License: Free tier (no license key set)")
			fmt.Println("Set AWSDENY_LICENSE_KEY to unlock Pro features.")
			return nil
		}

		lic, err := license.Validate(key)
		if err != nil {
			fmt.Printf("License: Invalid (%s)\n", err)
			return nil
		}

		fmt.Printf("License: %s\n", lic.Tier)
		fmt.Printf("Email:   %s\n", lic.Email)
		fmt.Printf("Expires: %s\n", lic.ExpiresAt.Format("2006-01-02"))

		if lic.InGracePeriod() {
			fmt.Println("Warning: License expired, in grace period")
		} else if lic.IsExpired() {
			fmt.Println("Warning: License expired")
		}

		return nil
	},
}

var (
	genEmail   string
	genTier    string
	genDays    int
	genPrivKey string
)

var licenseGenerateCmd = &cobra.Command{
	Use:    "generate",
	Short:  "Generate a license key (admin)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if genPrivKey == "" {
			return fmt.Errorf("--private-key is required")
		}
		if genEmail == "" {
			return fmt.Errorf("--email is required")
		}

		tier := license.Tier(genTier)
		if tier != license.TierPro && tier != license.TierCommercial {
			return fmt.Errorf("--tier must be 'pro' or 'commercial'")
		}

		duration := time.Duration(genDays) * 24 * time.Hour

		key, err := license.Generate(genPrivKey, genEmail, tier, duration)
		if err != nil {
			return fmt.Errorf("generating license: %w", err)
		}

		fmt.Println(key)
		return nil
	},
}

var licenseKeypairCmd = &cobra.Command{
	Use:    "keypair",
	Short:  "Generate a new Ed25519 key pair (admin)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := license.GenerateKeyPair()
		if err != nil {
			return err
		}
		fmt.Printf("Public key:  %s\n", pub)
		fmt.Printf("Private key: %s\n", priv)
		fmt.Println("\nSet public key at build time:")
		fmt.Printf("  go build -ldflags \"-X github.com/leredteam/awsdeny/license.publicKeyB64=%s\"\n", pub)
		return nil
	},
}

func init() {
	licenseCmd.AddCommand(licenseStatusCmd)
	licenseCmd.AddCommand(licenseGenerateCmd)
	licenseCmd.AddCommand(licenseKeypairCmd)

	licenseGenerateCmd.Flags().StringVar(&genEmail, "email", "", "License email")
	licenseGenerateCmd.Flags().StringVar(&genTier, "tier", "pro", "License tier (pro, commercial)")
	licenseGenerateCmd.Flags().IntVar(&genDays, "days", 365, "License duration in days")
	licenseGenerateCmd.Flags().StringVar(&genPrivKey, "private-key", "", "Ed25519 private key (base64)")
}
