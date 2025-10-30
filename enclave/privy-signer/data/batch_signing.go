package data

import (
	"fmt"
	"strings"
)

// BatchSignRequest represents a batch of signing requests from Axal backend
type BatchSignRequest struct {
	SigningRequests []SingleSignRequest `json:"signing_requests"`
}

// SingleSignRequest represents a single signing request within a batch
type SingleSignRequest struct {
	Hash        string `json:"hash"`
	PrivyID     string `json:"privy_id"`
	SigningType string `json:"signing_type"`
	Index       int    `json:"index"` // For maintaining order in response
}

// BatchSignResponse represents the response to a batch signing request
type BatchSignResponse struct {
	TotalRequests   int               `json:"total_requests"`
	SuccessfulSigns int               `json:"successful_signs"`
	FailedSigns     int               `json:"failed_signs"`
	Signatures      []SignatureResult `json:"signatures"`
}

// SignatureResult represents the result of a single signing operation within a batch
type SignatureResult struct {
	Index     int    `json:"index"`
	Success   bool   `json:"success"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ValidateBatchRequest validates the entire batch request
func (bsr *BatchSignRequest) ValidateBatchRequest() error {
	if len(bsr.SigningRequests) == 0 {
		return fmt.Errorf("batch request cannot be empty")
	}

	if len(bsr.SigningRequests) > 10000 {
		return fmt.Errorf("batch request too large: max 10000 requests, got %d", len(bsr.SigningRequests))
	}

	for i, req := range bsr.SigningRequests {
		if req.Hash == "" {
			return fmt.Errorf("hash is required for request %d", i)
		}
		if !strings.HasPrefix(req.Hash, "0x") {
			return fmt.Errorf("hash must start with 0x for request %d", i)
		}
		if req.PrivyID == "" {
			return fmt.Errorf("privy_id is required for request %d", i)
		}
		if req.SigningType != "axal" && req.SigningType != "user" {
			return fmt.Errorf("invalid signing_type for request %d: must be 'axal' or 'user'", i)
		}
	}

	return nil
}

// Helper function to create a new batch sign request
func NewBatchSignRequest(requests []SingleSignRequest) *BatchSignRequest {
	return &BatchSignRequest{
		SigningRequests: requests,
	}
}

// Helper function to create a single sign request
func NewSingleSignRequest(hash, privyID, signingType string, index int) SingleSignRequest {
	return SingleSignRequest{
		Hash:        hash,
		PrivyID:     privyID,
		SigningType: signingType,
		Index:       index,
	}
}
