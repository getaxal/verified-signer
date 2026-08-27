package data

import (
	"testing"
	"time"
)

const testOwnershipAddress = "0x1234567890abcdef1234567890abcdef12345678"

func ownershipChallenge(address string) string {
	return "crossmint.com wants you to sign in with your blockchain account:\n" + address +
		"\n\nI am signing this message to prove ownership of my wallet address " + address +
		" for Crossmint verification.\n\nURI: https://staging.crossmint.com\nVersion: 1" +
		"\nNonce: abc123\nIssued At: 2026-08-27T16:00:00Z" +
		"\nExpiration Time: 2026-08-27T17:00:00Z\nRequest ID: order-123\nChain ID: base-sepolia"
}

func validPersonalSignRequest() AxalEthPersonalSignRequest {
	var req AxalEthPersonalSignRequest
	req.Method = "personal_sign"
	req.Params.Message = ownershipChallenge(testOwnershipAddress)
	req.Params.Encoding = "utf-8"
	req.PrivyID = "did:privy:test"
	req.WalletAddress = testOwnershipAddress
	req.Purpose = CrossmintWalletOwnershipPurpose
	return req
}

func TestAxalEthPersonalSignRequestValidate(t *testing.T) {
	now := time.Date(2026, 8, 27, 16, 30, 0, 0, time.UTC)
	req := validPersonalSignRequest()
	if err := req.Validate(now); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}
}

func TestAxalEthPersonalSignRequestRejectsDifferentWallet(t *testing.T) {
	now := time.Date(2026, 8, 27, 16, 30, 0, 0, time.UTC)
	req := validPersonalSignRequest()
	req.WalletAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := req.Validate(now); err == nil {
		t.Fatal("expected wallet mismatch to be rejected")
	}
}

func TestPersonalSignAuthPayloadBindsInputs(t *testing.T) {
	req := validPersonalSignRequest()
	original := req.AuthPayload()
	req.Params.Message += " altered"
	if req.AuthPayload() == original {
		t.Fatal("expected message change to alter auth payload")
	}
}
