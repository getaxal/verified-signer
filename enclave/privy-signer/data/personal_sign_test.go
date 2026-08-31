package data

import (
	"strings"
	"testing"
)

const testOwnershipAddress = "0x1234567890abcdef1234567890abcdef12345678"

func validPersonalSignRequest() AxalEthPersonalSignRequest {
	var req AxalEthPersonalSignRequest
	req.Method = "personal_sign"
	req.Params.Message = "Sign in to Axal with this wallet"
	req.Params.Encoding = "utf-8"
	req.PrivyID = "did:privy:test"
	req.WalletAddress = testOwnershipAddress
	req.Purpose = "wallet_ownership"
	return req
}

func TestAxalEthPersonalSignRequestValidate(t *testing.T) {
	req := validPersonalSignRequest()
	if err := req.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}
}

func TestAxalEthPersonalSignRequestAcceptsHex(t *testing.T) {
	req := validPersonalSignRequest()
	req.Params.Message = "0x48656c6c6f"
	req.Params.Encoding = "hex"
	if err := req.Validate(); err != nil {
		t.Fatalf("expected valid hex request, got %v", err)
	}
}

func TestAxalEthPersonalSignRequestRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AxalEthPersonalSignRequest)
	}{
		{"method", func(req *AxalEthPersonalSignRequest) { req.Method = "eth_sign" }},
		{"purpose", func(req *AxalEthPersonalSignRequest) { req.Purpose = "Provider Login" }},
		{"privy ID", func(req *AxalEthPersonalSignRequest) { req.PrivyID = "" }},
		{"wallet", func(req *AxalEthPersonalSignRequest) { req.WalletAddress = "not-an-address" }},
		{"encoding", func(req *AxalEthPersonalSignRequest) { req.Params.Encoding = "base64" }},
		{"hex message", func(req *AxalEthPersonalSignRequest) {
			req.Params.Encoding = "hex"
			req.Params.Message = "0xnot-hex"
		}},
		{"empty message", func(req *AxalEthPersonalSignRequest) { req.Params.Message = "" }},
		{"large message", func(req *AxalEthPersonalSignRequest) {
			req.Params.Message = strings.Repeat("a", maxPersonalSignMessageBytes+1)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validPersonalSignRequest()
			tt.mutate(&req)
			if err := req.Validate(); err == nil {
				t.Fatal("expected invalid request to be rejected")
			}
		})
	}
}

func TestPersonalSignAuthPayloadBindsInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AxalEthPersonalSignRequest)
	}{
		{"method", func(req *AxalEthPersonalSignRequest) { req.Method = "other" }},
		{"purpose", func(req *AxalEthPersonalSignRequest) { req.Purpose = "other_purpose" }},
		{"encoding", func(req *AxalEthPersonalSignRequest) { req.Params.Encoding = "hex" }},
		{"wallet", func(req *AxalEthPersonalSignRequest) {
			req.WalletAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"message", func(req *AxalEthPersonalSignRequest) { req.Params.Message += " altered" }},
		{"privy ID", func(req *AxalEthPersonalSignRequest) { req.PrivyID = "did:privy:other" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validPersonalSignRequest()
			original := req.AuthPayload()
			tt.mutate(&req)
			if req.AuthPayload() == original {
				t.Fatal("expected input change to alter auth payload")
			}
		})
	}
}
