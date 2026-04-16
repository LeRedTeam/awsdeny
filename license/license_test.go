package license

import (
	"testing"
	"time"
)

func TestGenerateAndValidate(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Set the public key
	originalKey := publicKeyB64
	publicKeyB64 = pub
	defer func() { publicKeyB64 = originalKey }()

	// Generate a license
	key, err := Generate(priv, "test@example.com", TierPro, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if key == "" {
		t.Fatal("expected non-empty license key")
	}

	// Validate the license
	lic, err := Validate(key)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if lic.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %q", lic.Email)
	}
	if lic.Tier != TierPro {
		t.Errorf("expected tier pro, got %q", lic.Tier)
	}
	if !lic.IsPro() {
		t.Error("expected IsPro() to return true")
	}
	if lic.IsExpired() {
		t.Error("expected license to not be expired")
	}
}

func TestValidate_InvalidKey(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	originalKey := publicKeyB64
	publicKeyB64 = pub
	defer func() { publicKeyB64 = originalKey }()

	_, err = Validate("not-a-valid-key")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestValidate_ExpiredLicense(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	originalKey := publicKeyB64
	publicKeyB64 = pub
	defer func() { publicKeyB64 = originalKey }()

	// Generate an already-expired license (negative duration hack: generate then check)
	key, err := Generate(priv, "test@example.com", TierPro, -30*24*time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = Validate(key)
	if err == nil {
		t.Error("expected error for expired license")
	}
}

func TestValidate_NoPublicKey(t *testing.T) {
	originalKey := publicKeyB64
	publicKeyB64 = ""
	defer func() { publicKeyB64 = originalKey }()

	_, err := Validate("any-key")
	if err == nil {
		t.Error("expected error when no public key configured")
	}
}

func TestLicense_CommercialIsPro(t *testing.T) {
	lic := &License{Tier: TierCommercial}
	if !lic.IsPro() {
		t.Error("commercial tier should count as pro")
	}
}

func TestLicense_FreeIsNotPro(t *testing.T) {
	lic := &License{Tier: TierFree}
	if lic.IsPro() {
		t.Error("free tier should not be pro")
	}
}
