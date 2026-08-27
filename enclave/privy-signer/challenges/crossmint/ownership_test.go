package crossmint

import (
	"strings"
	"testing"
	"time"
)

const testOwnershipAddress = "0x1234567890abcdef1234567890abcdef12345678"

func ownershipChallenge(address string) string {
	return challengeHeader + "\n" + address +
		"\n\nI am signing this message to prove ownership of my wallet address " + address +
		" for Crossmint verification.\n\nURI: https://staging.crossmint.com\nVersion: 1" +
		"\nNonce: abc123\nIssued At: 2026-08-27T16:00:00Z" +
		"\nExpiration Time: 2026-08-27T17:00:00Z\nRequest ID: order-123\nChain ID: base-sepolia"
}

func TestValidateOwnership(t *testing.T) {
	now := time.Date(2026, 8, 27, 16, 30, 0, 0, time.UTC)
	if err := ValidateOwnership(ownershipChallenge(testOwnershipAddress), testOwnershipAddress, now); err != nil {
		t.Fatalf("expected valid challenge, got %v", err)
	}
}

func TestValidateOwnershipRejectsDifferentWallet(t *testing.T) {
	now := time.Date(2026, 8, 27, 16, 30, 0, 0, time.UTC)
	err := ValidateOwnership(
		ownershipChallenge(testOwnershipAddress),
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		now,
	)
	if err == nil {
		t.Fatal("expected wallet mismatch to be rejected")
	}
}

func TestValidateOwnershipRejectsExpiredChallenge(t *testing.T) {
	now := time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)
	if err := ValidateOwnership(ownershipChallenge(testOwnershipAddress), testOwnershipAddress, now); err == nil {
		t.Fatal("expected expired challenge to be rejected")
	}
}

func TestValidateOwnershipRejectsUntrustedURI(t *testing.T) {
	now := time.Date(2026, 8, 27, 16, 30, 0, 0, time.UTC)
	challenge := strings.Replace(
		ownershipChallenge(testOwnershipAddress),
		"https://staging.crossmint.com",
		"https://crossmint.com.attacker.example",
		1,
	)
	if err := ValidateOwnership(challenge, testOwnershipAddress, now); err == nil {
		t.Fatal("expected untrusted URI to be rejected")
	}
}

func TestValidateOwnershipAcceptsProductionAndCAIP2Base(t *testing.T) {
	now := time.Date(2026, 8, 27, 16, 30, 0, 0, time.UTC)
	challenge := strings.NewReplacer(
		"https://staging.crossmint.com", "https://crossmint.com",
		"Chain ID: base-sepolia", "Chain ID: eip155:8453",
	).Replace(ownershipChallenge(testOwnershipAddress))
	if err := ValidateOwnership(challenge, testOwnershipAddress, now); err != nil {
		t.Fatalf("expected production Base challenge to be valid, got %v", err)
	}
}
