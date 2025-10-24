package data

import (
	"encoding/json"
	"testing"
)

func TestBatchSignRequest_ValidateBatchRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *BatchSignRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid batch request",
			req: &BatchSignRequest{
				SigningRequests: []SingleSignRequest{
					{
						Hash:        "0x1234567890abcdef",
						PrivyID:     "did:privy:test123",
						SigningType: "axal",
						Index:       0,
					},
					{
						Hash:        "0xfedcba0987654321",
						PrivyID:     "did:privy:test456",
						SigningType: "user",
						Index:       1,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty batch request",
			req: &BatchSignRequest{
				SigningRequests: []SingleSignRequest{},
			},
			wantErr: true,
			errMsg:  "batch request cannot be empty",
		},
		{
			name: "missing hash",
			req: &BatchSignRequest{
				SigningRequests: []SingleSignRequest{
					{
						Hash:        "",
						PrivyID:     "did:privy:test123",
						SigningType: "axal",
						Index:       0,
					},
				},
			},
			wantErr: true,
			errMsg:  "hash is required for request 0",
		},
		{
			name: "invalid hash format",
			req: &BatchSignRequest{
				SigningRequests: []SingleSignRequest{
					{
						Hash:        "1234567890abcdef", // Missing 0x prefix
						PrivyID:     "did:privy:test123",
						SigningType: "axal",
						Index:       0,
					},
				},
			},
			wantErr: true,
			errMsg:  "hash must start with 0x for request 0",
		},
		{
			name: "missing privy_id",
			req: &BatchSignRequest{
				SigningRequests: []SingleSignRequest{
					{
						Hash:        "0x1234567890abcdef",
						PrivyID:     "",
						SigningType: "axal",
						Index:       0,
					},
				},
			},
			wantErr: true,
			errMsg:  "privy_id is required for request 0",
		},
		{
			name: "invalid signing type",
			req: &BatchSignRequest{
				SigningRequests: []SingleSignRequest{
					{
						Hash:        "0x1234567890abcdef",
						PrivyID:     "did:privy:test123",
						SigningType: "invalid",
						Index:       0,
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid signing_type for request 0: must be 'axal' or 'user'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateBatchRequest()
			if tt.wantErr {
				if err == nil {
					t.Errorf("BatchSignRequest.ValidateBatchRequest() expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("BatchSignRequest.ValidateBatchRequest() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("BatchSignRequest.ValidateBatchRequest() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestNewBatchSignRequest(t *testing.T) {
	requests := []SingleSignRequest{
		{
			Hash:        "0x1234567890abcdef",
			PrivyID:     "did:privy:test123",
			SigningType: "axal",
			Index:       0,
		},
		{
			Hash:        "0xfedcba0987654321",
			PrivyID:     "did:privy:test456",
			SigningType: "user",
			Index:       1,
		},
	}

	batch := NewBatchSignRequest(requests)

	if len(batch.SigningRequests) != 2 {
		t.Errorf("NewBatchSignRequest() length = %d, want 2", len(batch.SigningRequests))
	}

	if batch.SigningRequests[0].Hash != "0x1234567890abcdef" {
		t.Errorf("NewBatchSignRequest() first hash = %s, want 0x1234567890abcdef", batch.SigningRequests[0].Hash)
	}
}

func TestNewSingleSignRequest(t *testing.T) {
	req := NewSingleSignRequest("0x1234567890abcdef", "did:privy:test123", "axal", 5)

	if req.Hash != "0x1234567890abcdef" {
		t.Errorf("NewSingleSignRequest() hash = %s, want 0x1234567890abcdef", req.Hash)
	}
	if req.PrivyID != "did:privy:test123" {
		t.Errorf("NewSingleSignRequest() privyID = %s, want did:privy:test123", req.PrivyID)
	}
	if req.SigningType != "axal" {
		t.Errorf("NewSingleSignRequest() signingType = %s, want axal", req.SigningType)
	}
	if req.Index != 5 {
		t.Errorf("NewSingleSignRequest() index = %d, want 5", req.Index)
	}
}

func TestBatchSignRequest_JSONSerialization(t *testing.T) {
	requests := []SingleSignRequest{
		{
			Hash:        "0x1234567890abcdef",
			PrivyID:     "did:privy:test123",
			SigningType: "axal",
			Index:       0,
		},
	}

	batch := NewBatchSignRequest(requests)

	// Test JSON marshaling
	jsonData, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled BatchSignRequest
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify the unmarshaled data
	if len(unmarshaled.SigningRequests) != 1 {
		t.Errorf("Unmarshaled length = %d, want 1", len(unmarshaled.SigningRequests))
	}

	if unmarshaled.SigningRequests[0].Hash != batch.SigningRequests[0].Hash {
		t.Errorf("Unmarshaled Hash = %v, want %v", unmarshaled.SigningRequests[0].Hash, batch.SigningRequests[0].Hash)
	}
}

func TestBatchSignResponse_JSONSerialization(t *testing.T) {
	response := BatchSignResponse{
		TotalRequests:   2,
		SuccessfulSigns: 1,
		FailedSigns:     1,
		Signatures: []SignatureResult{
			{
				Index:     0,
				Success:   true,
				Signature: "0xabcdef1234567890",
			},
			{
				Index:   1,
				Success: false,
				Error:   "invalid privy_id",
			},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled BatchSignResponse
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify the unmarshaled data
	if unmarshaled.TotalRequests != response.TotalRequests {
		t.Errorf("Unmarshaled TotalRequests = %d, want %d", unmarshaled.TotalRequests, response.TotalRequests)
	}
	if unmarshaled.SuccessfulSigns != response.SuccessfulSigns {
		t.Errorf("Unmarshaled SuccessfulSigns = %d, want %d", unmarshaled.SuccessfulSigns, response.SuccessfulSigns)
	}
	if len(unmarshaled.Signatures) != 2 {
		t.Errorf("Unmarshaled Signatures length = %d, want 2", len(unmarshaled.Signatures))
	}
}
