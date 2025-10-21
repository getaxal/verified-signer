package data

import (
	"encoding/json"
	"testing"
)

func TestNewEthSecp256k1SignRequest(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want *EthSecp256k1SignRequest
	}{
		{
			name: "valid hash",
			hash: "0x1234567890abcdef",
			want: &EthSecp256k1SignRequest{
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
			want: &EthSecp256k1SignRequest{
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
			want: &EthSecp256k1SignRequest{
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
			got := NewEthSecp256k1SignRequest(tt.hash)
			if got.Method != tt.want.Method {
				t.Errorf("NewEthSecp256k1SignRequest() Method = %v, want %v", got.Method, tt.want.Method)
			}
			if got.Params.Hash != tt.want.Params.Hash {
				t.Errorf("NewEthSecp256k1SignRequest() Hash = %v, want %v", got.Params.Hash, tt.want.Params.Hash)
			}
		})
	}
}

func TestEthSecp256k1SignRequest_ValidateTxRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *EthSecp256k1SignRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid method",
			req: &EthSecp256k1SignRequest{
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
			req: &EthSecp256k1SignRequest{
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
			req: &EthSecp256k1SignRequest{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateTxRequest()
			if tt.wantErr {
				if err == nil {
					t.Errorf("EthSecp256k1SignRequest.ValidateTxRequest() expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("EthSecp256k1SignRequest.ValidateTxRequest() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("EthSecp256k1SignRequest.ValidateTxRequest() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestEthSecp256k1SignRequest_GetMethod(t *testing.T) {
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
			req := &EthSecp256k1SignRequest{
				Method: tt.method,
				Params: struct {
					Hash string `json:"hash"`
				}{
					Hash: "0x1234",
				},
			}
			if got := req.GetMethod(); got != tt.want {
				t.Errorf("EthSecp256k1SignRequest.GetMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEthSecp256k1SignRequest_Interface(t *testing.T) {
	// Test that EthSecp256k1SignRequest implements EthTxRequest interface
	var _ EthTxRequest = (*EthSecp256k1SignRequest)(nil)

	req := NewEthSecp256k1SignRequest("0x1234567890abcdef")

	// Test interface methods
	if method := req.GetMethod(); method != "secp256k1_sign" {
		t.Errorf("GetMethod() = %v, want secp256k1_sign", method)
	}

	if err := req.ValidateTxRequest(); err != nil {
		t.Errorf("ValidateTxRequest() unexpected error = %v", err)
	}
}

func TestEthSecp256k1SignRequest_JSONSerialization(t *testing.T) {
	req := NewEthSecp256k1SignRequest("0x1234567890abcdef")

	// Test JSON marshaling
	jsonData, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled EthSecp256k1SignRequest
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
