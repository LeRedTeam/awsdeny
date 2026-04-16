package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// GenerateKeyPair creates a new Ed25519 key pair for license signing.
// Returns base64-encoded public and private keys.
func GenerateKeyPair() (publicKey, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", fmt.Errorf("generating key pair: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub),
		base64.StdEncoding.EncodeToString(priv),
		nil
}

// Generate creates a signed license key.
func Generate(privateKeyB64, email string, tier Tier, duration time.Duration) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}

	privKey := ed25519.PrivateKey(privKeyBytes)

	now := time.Now().UTC()
	payload := licensePayload{
		Email:     email,
		Tier:      string(tier),
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(duration).Format(time.RFC3339),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	signature := ed25519.Sign(privKey, payloadBytes)

	lk := licenseKey{
		Payload:   base64.StdEncoding.EncodeToString(payloadBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	keyBytes, err := json.Marshal(lk)
	if err != nil {
		return "", fmt.Errorf("marshaling license key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(keyBytes), nil
}
