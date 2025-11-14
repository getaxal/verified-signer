package data

import (
	"encoding/json"
	"testing"
)

func TestNewUserEthSecp256k1SignRequest(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want *UserEthSecp256k1SignRequest
	}{
		{
			name: "valid hash",
			hash: "0x1234567890abcdef",
			want: &UserEthSecp256k1SignRequest{
				Method: "secp256k1_sign",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234567890abcdef",
				},
			},
		},
		{
			name: "empty hash",
			hash: "",
			want: &UserEthSecp256k1SignRequest{
				Method: "secp256k1_sign",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "",
				},
			},
		},
		{
			name: "long hash",
			hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
			want: &UserEthSecp256k1SignRequest{
				Method: "secp256k1_sign",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewUserEthSecp256k1SignRequest(tt.hash)
			if got.Method != tt.want.Method {
				t.Errorf("NewUserEthSecp256k1SignRequest() Method = %v, want %v", got.Method, tt.want.Method)
			}
			if got.Params.Hash != tt.want.Params.Hash {
				t.Errorf("NewUserEthSecp256k1SignRequest() Hash = %v, want %v", got.Params.Hash, tt.want.Params.Hash)
			}
		})
	}
}

func TestUserEthSecp256k1SignRequest_ValidateTxRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *UserEthSecp256k1SignRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid method",
			req: &UserEthSecp256k1SignRequest{
				Method: "secp256k1_sign",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid method",
			req: &UserEthSecp256k1SignRequest{
				Method: "invalid_method",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234",
				},
			},
			wantErr: true,
			errMsg:  "incorrect transaction request method",
		},
		{
			name: "empty method",
			req: &UserEthSecp256k1SignRequest{
				Method: "",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234",
				},
			},
			wantErr: true,
			errMsg:  "incorrect transaction request method",
		},
		{
			name: "empty hash",
			req: &UserEthSecp256k1SignRequest{
				Method: "secp256k1_sign",
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "",
				},
			},
			wantErr: true,
			errMsg:  "hash is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateTxRequest()
			if tt.wantErr {
				if err == nil {
					t.Errorf("UserEthSecp256k1SignRequest.ValidateTxRequest() expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("UserEthSecp256k1SignRequest.ValidateTxRequest() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("UserEthSecp256k1SignRequest.ValidateTxRequest() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestUserEthSecp256k1SignRequest_GetMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   string
	}{
		{
			name:   "correct method",
			method: "secp256k1_sign",
			want:   "secp256k1_sign",
		},
		{
			name:   "incorrect method",
			method: "wrong_method",
			want:   "wrong_method",
		},
		{
			name:   "empty method",
			method: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &UserEthSecp256k1SignRequest{
				Method: tt.method,
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234",
				},
			}
			if got := req.GetMethod(); got != tt.want {
				t.Errorf("UserEthSecp256k1SignRequest.GetMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserEthSecp256k1SignRequest_Interface(t *testing.T) {
	// Test that UserEthSecp256k1SignRequest implements EthTxRequest interface
	var _ EthTxRequest = (*UserEthSecp256k1SignRequest)(nil)

	req := NewUserEthSecp256k1SignRequest("0x1234567890abcdef")

	// Test interface methods
	if method := req.GetMethod(); method != "secp256k1_sign" {
		t.Errorf("GetMethod() = %v, want secp256k1_sign", method)
	}

	if err := req.ValidateTxRequest(); err != nil {
		t.Errorf("ValidateTxRequest() unexpected error = %v", err)
	}
}

func TestAxalEthSecp256k1SignRequest_Interface(t *testing.T) {
	// Test that AxalEthSecp256k1SignRequest implements EthTxRequest interface
	var _ EthTxRequest = (*AxalEthSecp256k1SignRequest)(nil)

	req := NewAxalEthSecp256k1SignRequest("0x1234567890abcdef", "did:privy:test123")

	// Test interface methods
	if method := req.GetMethod(); method != "secp256k1_sign" {
		t.Errorf("GetMethod() = %v, want secp256k1_sign", method)
	}

	if err := req.ValidateTxRequest(); err != nil {
		t.Errorf("ValidateTxRequest() unexpected error = %v", err)
	}
}

func TestUserEthSecp256k1SignRequest_JSONSerialization(t *testing.T) {
	req := NewUserEthSecp256k1SignRequest("0x1234567890abcdef")

	// Test JSON marshaling
	jsonData, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled UserEthSecp256k1SignRequest
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify the unmarshaled data
	if unmarshaled.Method != req.Method {
		t.Errorf("Unmarshaled Method = %v, want %v", unmarshaled.Method, req.Method)
	}
	if unmarshaled.Params.Hash != req.Params.Hash {
		t.Errorf("Unmarshaled Hash = %v, want %v", unmarshaled.Params.Hash, req.Params.Hash)
	}

	// Test expected JSON structure
	expectedJSON := `{"method":"secp256k1_sign","params":{"hash":"0x1234567890abcdef"}}`
	var expected map[string]interface{}
	var actual map[string]interface{}

	if err := json.Unmarshal([]byte(expectedJSON), &expected); err != nil {
		t.Fatalf("Failed to unmarshal expected JSON: %v", err)
	}
	if err := json.Unmarshal(jsonData, &actual); err != nil {
		t.Fatalf("Failed to unmarshal actual JSON: %v", err)
	}

	if actual["method"] != expected["method"] {
		t.Errorf("JSON method = %v, want %v", actual["method"], expected["method"])
	}
}

func TestAxalEthSecp256k1SignRequest_JSONSerialization(t *testing.T) {
	req := NewAxalEthSecp256k1SignRequest("0x1234567890abcdef", "did:privy:test123")

	// Test JSON marshaling
	jsonData, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled AxalEthSecp256k1SignRequest
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify the unmarshaled data
	if unmarshaled.Method != req.Method {
		t.Errorf("Unmarshaled Method = %v, want %v", unmarshaled.Method, req.Method)
	}
	if unmarshaled.Params.Hash != req.Params.Hash {
		t.Errorf("Unmarshaled Hash = %v, want %v", unmarshaled.Params.Hash, req.Params.Hash)
	}
	if unmarshaled.PrivyID != req.PrivyID {
		t.Errorf("Unmarshaled PrivyID = %v, want %v", unmarshaled.PrivyID, req.PrivyID)
	}

	// Test expected JSON structure includes privy_id
	expectedJSON := `{"method":"secp256k1_sign","params":{"hash":"0x1234567890abcdef"},"privy_id":"did:privy:test123"}`
	var expected map[string]interface{}
	var actual map[string]interface{}

	if err := json.Unmarshal([]byte(expectedJSON), &expected); err != nil {
		t.Fatalf("Failed to unmarshal expected JSON: %v", err)
	}
	if err := json.Unmarshal(jsonData, &actual); err != nil {
		t.Fatalf("Failed to unmarshal actual JSON: %v", err)
	}

	if actual["method"] != expected["method"] {
		t.Errorf("JSON method = %v, want %v", actual["method"], expected["method"])
	}
	if actual["privy_id"] != expected["privy_id"] {
		t.Errorf("JSON privy_id = %v, want %v", actual["privy_id"], expected["privy_id"])
	}
}

func TestEthSecp256k1SignResponseData_JSONSerialization(t *testing.T) {
	responseData := EthSecp256k1SignResponseData{
		Signature: "0xabcdef1234567890",
		Encoding:  "hex",
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(responseData)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled EthSecp256k1SignResponseData
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify the unmarshaled data
	if unmarshaled.Signature != responseData.Signature {
		t.Errorf("Unmarshaled Signature = %v, want %v", unmarshaled.Signature, responseData.Signature)
	}
	if unmarshaled.Encoding != responseData.Encoding {
		t.Errorf("Unmarshaled Encoding = %v, want %v", unmarshaled.Encoding, responseData.Encoding)
	}
}

func TestEthSecp256k1SignResponse_JSONSerialization(t *testing.T) {
	response := EthSecp256k1SignResponse{
		Method: "secp256k1_sign",
		Data: EthSecp256k1SignResponseData{
			Signature: "0xabcdef1234567890",
			Encoding:  "hex",
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled EthSecp256k1SignResponse
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify the unmarshaled data
	if unmarshaled.Method != response.Method {
		t.Errorf("Unmarshaled Method = %v, want %v", unmarshaled.Method, response.Method)
	}
	if unmarshaled.Data.Signature != response.Data.Signature {
		t.Errorf("Unmarshaled Signature = %v, want %v", unmarshaled.Data.Signature, response.Data.Signature)
	}
	if unmarshaled.Data.Encoding != response.Data.Encoding {
		t.Errorf("Unmarshaled Encoding = %v, want %v", unmarshaled.Data.Encoding, response.Data.Encoding)
	}
}
