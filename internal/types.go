package internal

// ParsedError represents the extracted fields from an AccessDenied error message.
type ParsedError struct {
	// Always extracted (Level 1)
	RawMessage string
	Action     string // e.g., "s3:GetObject"
	Resource   string // e.g., "arn:aws:s3:::bucket/key"
	Principal  string // e.g., "arn:aws:iam::123:role/MyRole"

	// Sometimes extracted (enriched errors)
	DenyType   string // "explicit" or "implicit"
	PolicyType string // "scp", "identity", "resource", "boundary", "session"
	PolicyARN  string // ARN of the specific policy (if provided)
	Reason     string // Human text from AWS (if provided)

	// From AWS CLI wrapper
	ErrorCode string // e.g., "AccessDenied", "AccessDeniedException"
	Operation string // e.g., "GetObject", "Invoke"

	// From EC2 encoded errors
	EncodedMessage string

	// From CloudTrail (Level 4)
	SourceIP       string
	UserAgent      string
	EventTime      string
	Region         string
	AccountID      string
	VPCEndpointID  string
	SessionContext map[string]string

	// Metadata
	Format     string // Which format was matched (A, B, C, etc.)
	ParseLevel int    // How much was extracted (1-4)
}

// Explanation is the analysis result presented to the user.
type Explanation struct {
	Summary          string       // One-line summary
	DenyType         string       // "explicit" or "implicit"
	SourceType       string       // "scp", "identity", "resource", "boundary", "session", "vpce", "unknown"
	SourceARN        string       // If known
	Reason           string       // Detailed human-readable reason
	Suggestions      []Suggestion // Ordered by likelihood of success
	Confidence       string       // "low", "medium", "high", "very-high"
	ConfidenceReason string       // Why this confidence level
	Level            int          // Which analysis level produced this
	HeuristicID      string       // Which heuristic matched (if any)
	Warnings         []string     // Any warnings (e.g., enrichment failed)
}

// Suggestion is an actionable fix recommendation.
type Suggestion struct {
	Action     string // What to do
	Difficulty string // "easy", "medium", "hard"
	Requires   string // Who/what is needed (e.g., "org admin", "bucket owner")
}

// EnrichmentResult holds data from AWS API calls (Levels 2-3).
type EnrichmentResult struct {
	PolicyFetched         bool
	PolicyDocument        string
	MatchingStatements    []PolicyStatement
	SimulationRan         bool
	SimulationResult      string // "allowed", "implicitDeny", "explicitDeny"
	SimulationConfirms    bool
	SimulationContradicts bool
	DecodedMessage        string // From sts:DecodeAuthorizationMessage
	Warnings              []string
}

// PolicyStatement represents a single statement from an IAM policy document.
type PolicyStatement struct {
	Sid        string
	Effect     string
	Actions    []string
	Resources  []string
	Conditions map[string]map[string][]string
}

// AnalysisResult is the complete result combining all analysis levels.
type AnalysisResult struct {
	Parsed      ParsedError
	Explanation Explanation
	Enrichment  *EnrichmentResult
}
