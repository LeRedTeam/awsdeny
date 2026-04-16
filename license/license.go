package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// publicKey is the Ed25519 public key embedded at build time.
// Override with -ldflags "-X github.com/leredteam/awsdeny/license.publicKeyB64=..."
var publicKeyB64 = ""

// Tier represents the license tier.
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierCommercial Tier = "commercial"
)

// License represents a validated license.
type License struct {
	Email      string    `json:"email"`
	Tier       Tier      `json:"tier"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// licensePayload is the signed payload within the license key.
type licensePayload struct {
	Email     string `json:"email"`
	Tier      string `json:"tier"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

// licenseKey is the full license key structure.
type licenseKey struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

const gracePeriod = 7 * 24 * time.Hour

// Validate validates a license key string and returns the license.
func Validate(key string) (*License, error) {
	if publicKeyB64 == "" {
		return nil, fmt.Errorf("no public key configured (development build)")
	}

	pubKey, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}

	// Decode the license key
	keyData, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid license key format")
	}

	var lk licenseKey
	if err := json.Unmarshal(keyData, &lk); err != nil {
		return nil, fmt.Errorf("invalid license key structure")
	}

	// Verify signature
	payloadBytes, err := base64.StdEncoding.DecodeString(lk.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid license payload")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(lk.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid license signature")
	}

	if !ed25519.Verify(pubKey, payloadBytes, sigBytes) {
		return nil, fmt.Errorf("license signature verification failed")
	}

	// Parse payload
	var payload licensePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid license payload data")
	}

	issuedAt, err := time.Parse(time.RFC3339, payload.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid issued_at date")
	}

	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at date")
	}

	lic := &License{
		Email:     payload.Email,
		Tier:      Tier(payload.Tier),
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}

	// Check expiration with grace period
	if time.Now().After(expiresAt.Add(gracePeriod)) {
		return lic, fmt.Errorf("license expired on %s (grace period ended %s)",
			expiresAt.Format("2006-01-02"),
			expiresAt.Add(gracePeriod).Format("2006-01-02"))
	}

	return lic, nil
}

// IsExpired returns true if the license is past its expiry (ignoring grace period).
func (l *License) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// InGracePeriod returns true if the license is expired but within the grace period.
func (l *License) InGracePeriod() bool {
	now := time.Now()
	return now.After(l.ExpiresAt) && now.Before(l.ExpiresAt.Add(gracePeriod))
}

// IsPro returns true if the license grants Pro features.
func (l *License) IsPro() bool {
	return l.Tier == TierPro || l.Tier == TierCommercial
}

// CheckProFeature validates that the license allows Pro features.
// Returns nil if allowed, or an error explaining why not.
func CheckProFeature(key string, feature string) error {
	if key == "" {
		return fmt.Errorf("%s requires a Pro license. Set AWSDENY_LICENSE_KEY or get a license at https://github.com/leredteam/awsdeny", feature)
	}

	lic, err := Validate(key)
	if err != nil {
		return fmt.Errorf("license validation failed: %w", err)
	}

	if !lic.IsPro() {
		return fmt.Errorf("%s requires a Pro license (current: %s)", feature, lic.Tier)
	}

	if lic.InGracePeriod() {
		fmt.Printf("Warning: License expired on %s. Grace period ends %s.\n",
			lic.ExpiresAt.Format("2006-01-02"),
			lic.ExpiresAt.Add(gracePeriod).Format("2006-01-02"))
	}

	return nil
}
