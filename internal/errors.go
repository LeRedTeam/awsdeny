package internal

import "fmt"

// ExitCode represents CLI exit codes.
type ExitCode int

const (
	ExitSuccess          ExitCode = 0
	ExitGeneralError     ExitCode = 1
	ExitInvalidArgs      ExitCode = 2
	ExitParseError       ExitCode = 3
	ExitLicenseError     ExitCode = 4
	ExitEnrichmentError  ExitCode = 5
)

// ParseError indicates the error message could not be parsed.
type ParseError struct {
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("could not parse error: %s", e.Message)
}

// LicenseError indicates a license validation failure.
type LicenseError struct {
	Message string
}

func (e *LicenseError) Error() string {
	return fmt.Sprintf("license error: %s", e.Message)
}

// EnrichmentError indicates an AWS API call failure during enrichment.
type EnrichmentError struct {
	API     string
	Message string
}

func (e *EnrichmentError) Error() string {
	return fmt.Sprintf("enrichment failed (%s): %s", e.API, e.Message)
}
