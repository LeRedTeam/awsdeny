package internal

// ExitCode represents CLI exit codes.
type ExitCode int

const (
	ExitSuccess         ExitCode = 0
	ExitGeneralError    ExitCode = 1
	ExitInvalidArgs     ExitCode = 2
	ExitParseError      ExitCode = 3
	ExitLicenseError    ExitCode = 4
	ExitEnrichmentError ExitCode = 5
)

// ExitError wraps an error with a specific exit code for cobra to handle.
type ExitError struct {
	Code ExitCode
	Msg  string
}

func (e *ExitError) Error() string {
	return e.Msg
}

// NewExitError creates an ExitError.
func NewExitError(code ExitCode, msg string) *ExitError {
	return &ExitError{Code: code, Msg: msg}
}
