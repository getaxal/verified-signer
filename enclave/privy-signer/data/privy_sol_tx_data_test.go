package data

import (
	"testing"
)

// Test data constants
const (
	validBase64Transaction = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDRpb0mdmKftapwzzqUtlcDnuWbw8vwlyiyuWyyieQFKESezu52HWNss0SAcb60ftz7DSpgTwUmfUSl1CYHJ91GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAScgJ7J0AXFr1azCEvB1Y5zpiF4eXR+yTW0UB7am+E/MBAgIAAQwCAAAAQEIPAAAAAAA="
	validCAIP2             = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	validBase64Message     = "SGVsbG8gV29ybGQ="
	validSignature         = "3yZe7d4HhcPnNfJLxqjKkqJQMzwJfQEYgMdYFCZCGxEq5zKdEVRGz7PtKjJxQjXbGwD8nTHaRJzFzFcD3zPvKjMp"
)

// Tests for SolSignTransactionRequest
func TestNewSolSignTransactionRequest(t *testing.T) {
	tx := &SolTransaction{
		Transaction: validBase64Transaction,
		Encoding:    "base64",
	}

	req := NewSolSignTransactionRequest(tx)

	if req.Method != "signTransaction" {
		t.Errorf("Expected method to be 'signTransaction', got %s", req.Method)
	}

	if req.Transaction.Transaction != validBase64Transaction {
		t.Errorf("Expected transaction to be %s, got %s", validBase64Transaction, req.Transaction.Transaction)
	}

	if req.Transaction.Encoding != "base64" {
		t.Errorf("Expected encoding to be 'base64', got %s", req.Transaction.Encoding)
	}
}

func TestSolSignTransactionRequest_ValidateTxRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *SolSignTransactionRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			req: &SolSignTransactionRequest{
				Method: "signTransaction",
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "base64",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid method",
			req: &SolSignTransactionRequest{
				Method: "invalidMethod",
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "base64",
				},
			},
			expectError: true,
			errorMsg:    "incorrect transaction request method",
		},
		{
			name: "Missing transaction data",
			req: &SolSignTransactionRequest{
				Method: "signTransaction",
				Transaction: SolTransaction{
					Transaction: "",
					Encoding:    "base64",
				},
			},
			expectError: true,
			errorMsg:    "missing transaction data, it is required",
		},
		{
			name: "Invalid encoding",
			req: &SolSignTransactionRequest{
				Method: "signTransaction",
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "hex",
				},
			},
			expectError: true,
			errorMsg:    "Inavid encoding format, only base64 accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateTxRequest()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
			}
		})
	}
}

func TestSolSignTransactionRequest_GetTransaction(t *testing.T) {
	tx := &SolTransaction{
		Transaction: validBase64Transaction,
		Encoding:    "base64",
	}
	req := NewSolSignTransactionRequest(tx)

	result := req.GetTransaction()
	if result.Transaction != validBase64Transaction {
		t.Errorf("Expected transaction to be %s, got %s", validBase64Transaction, result.Transaction)
	}
	if result.Encoding != "base64" {
		t.Errorf("Expected encoding to be 'base64', got %s", result.Encoding)
	}
}

func TestSolSignTransactionRequest_GetMethod(t *testing.T) {
	tx := &SolTransaction{
		Transaction: validBase64Transaction,
		Encoding:    "base64",
	}
	req := NewSolSignTransactionRequest(tx)

	if req.GetMethod() != "signTransaction" {
		t.Errorf("Expected method to be 'signTransaction', got %s", req.GetMethod())
	}
}

// Tests for SolSignAndSendTransactionRequest
func TestNewSolSignAndSendTransactionRequest(t *testing.T) {
	tx := &SolTransaction{
		Transaction: validBase64Transaction,
		Encoding:    "base64",
	}

	req := NewSolSignAndSendTransactionRequest(tx, validCAIP2)

	if req.Method != "signAndSendTransaction" {
		t.Errorf("Expected method to be 'signAndSendTransaction', got %s", req.Method)
	}

	if req.CAIP2 != validCAIP2 {
		t.Errorf("Expected CAIP2 to be %s, got %s", validCAIP2, req.CAIP2)
	}

	if req.Transaction.Transaction != validBase64Transaction {
		t.Errorf("Expected transaction to be %s, got %s", validBase64Transaction, req.Transaction.Transaction)
	}
}

func TestSolSignAndSendTransactionRequest_ValidateTxRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *SolSignAndSendTransactionRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			req: &SolSignAndSendTransactionRequest{
				Method: "signAndSendTransaction",
				CAIP2:  validCAIP2,
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "base64",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid method",
			req: &SolSignAndSendTransactionRequest{
				Method: "invalidMethod",
				CAIP2:  validCAIP2,
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "base64",
				},
			},
			expectError: true,
			errorMsg:    "incorrect transaction request method",
		},
		{
			name: "Missing transaction data",
			req: &SolSignAndSendTransactionRequest{
				Method: "signAndSendTransaction",
				CAIP2:  validCAIP2,
				Transaction: SolTransaction{
					Transaction: "",
					Encoding:    "base64",
				},
			},
			expectError: true,
			errorMsg:    "missing transaction data, it is required",
		},
		{
			name: "Missing CAIP2",
			req: &SolSignAndSendTransactionRequest{
				Method: "signAndSendTransaction",
				CAIP2:  "",
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "base64",
				},
			},
			expectError: true,
			errorMsg:    "missing CAIP2 field in the transaction, it is required",
		},
		{
			name: "Invalid encoding",
			req: &SolSignAndSendTransactionRequest{
				Method: "signAndSendTransaction",
				CAIP2:  validCAIP2,
				Transaction: SolTransaction{
					Transaction: validBase64Transaction,
					Encoding:    "hex",
				},
			},
			expectError: true,
			errorMsg:    "Inavid encoding format, only base64 accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateTxRequest()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
			}
		})
	}
}

func TestSolSignAndSendTransactionRequest_GetTransaction(t *testing.T) {
	tx := &SolTransaction{
		Transaction: validBase64Transaction,
		Encoding:    "base64",
	}
	req := NewSolSignAndSendTransactionRequest(tx, validCAIP2)

	result := req.GetTransaction()
	if result.Transaction != validBase64Transaction {
		t.Errorf("Expected transaction to be %s, got %s", validBase64Transaction, result.Transaction)
	}
	if result.Encoding != "base64" {
		t.Errorf("Expected encoding to be 'base64', got %s", result.Encoding)
	}
}

func TestSolSignAndSendTransactionRequest_GetMethod(t *testing.T) {
	tx := &SolTransaction{
		Transaction: validBase64Transaction,
		Encoding:    "base64",
	}
	req := NewSolSignAndSendTransactionRequest(tx, validCAIP2)

	if req.GetMethod() != "signAndSendTransaction" {
		t.Errorf("Expected method to be 'signAndSendTransaction', got %s", req.GetMethod())
	}
}

// Tests for SolSignMessageRequest
func TestNewSolSignMessageRequest(t *testing.T) {
	req := NewSolSignMessageRequest(validBase64Message)

	if req.Method != "signMessage" {
		t.Errorf("Expected method to be 'signMessage', got %s", req.Method)
	}

	if req.Params.Message != validBase64Message {
		t.Errorf("Expected message to be %s, got %s", validBase64Message, req.Params.Message)
	}

	if req.Params.Encoding != "base64" {
		t.Errorf("Expected encoding to be 'base64', got %s", req.Params.Encoding)
	}
}

func TestSolSignMessageRequest_ValidateTxRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *SolSignMessageRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			req: &SolSignMessageRequest{
				Method: "signMessage",
				Params: struct {
					Message  string `json:"message"`
					Encoding string `json:"encoding"`
				}{
					Message:  validBase64Message,
					Encoding: "base64",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid method",
			req: &SolSignMessageRequest{
				Method: "invalidMethod",
				Params: struct {
					Message  string `json:"message"`
					Encoding string `json:"encoding"`
				}{
					Message:  validBase64Message,
					Encoding: "base64",
				},
			},
			expectError: true,
			errorMsg:    "incorrect transaction request method",
		},
		{
			name: "Missing message",
			req: &SolSignMessageRequest{
				Method: "signMessage",
				Params: struct {
					Message  string `json:"message"`
					Encoding string `json:"encoding"`
				}{
					Message:  "",
					Encoding: "base64",
				},
			},
			expectError: true,
			errorMsg:    "missing message field in the transaction, it is required",
		},
		{
			name: "Invalid encoding",
			req: &SolSignMessageRequest{
				Method: "signMessage",
				Params: struct {
					Message  string `json:"message"`
					Encoding string `json:"encoding"`
				}{
					Message:  validBase64Message,
					Encoding: "hex",
				},
			},
			expectError: true,
			errorMsg:    "Inavid encoding format, only base64 accepted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateTxRequest()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
			}
		})
	}
}

func TestSolSignMessageRequest_GetTransaction(t *testing.T) {
	req := NewSolSignMessageRequest(validBase64Message)
	result := req.GetTransaction()

	if result != nil {
		t.Errorf("Expected GetTransaction to return nil for message request, got %v", result)
	}
}

func TestSolSignMessageRequest_GetMethod(t *testing.T) {
	req := NewSolSignMessageRequest(validBase64Message)

	if req.GetMethod() != "signMessage" {
		t.Errorf("Expected method to be 'signMessage', got %s", req.GetMethod())
	}
}

// Tests for Response structures
func TestSolSignTransactionResponse(t *testing.T) {
	response := SolSignTransactionResponse{
		Method: "signTransaction",
		Data: SolSignTransactionResponseData{
			Signature: validSignature,
			Encoding:  "base64",
		},
	}

	if response.Method != "signTransaction" {
		t.Errorf("Expected method to be 'signTransaction', got %s", response.Method)
	}

	if response.Data.Signature != validSignature {
		t.Errorf("Expected signature to be %s, got %s", validSignature, response.Data.Signature)
	}

	if response.Data.Encoding != "base64" {
		t.Errorf("Expected encoding to be 'base64', got %s", response.Data.Encoding)
	}
}

func TestSolSignMessageResponse(t *testing.T) {
	response := SolSignMessageResponse{
		Method: "signMessage",
		Data: SolSignMessageResponseData{
			Signature: validSignature,
			Encoding:  "base64",
		},
	}

	if response.Method != "signMessage" {
		t.Errorf("Expected method to be 'signMessage', got %s", response.Method)
	}

	if response.Data.Signature != validSignature {
		t.Errorf("Expected signature to be %s, got %s", validSignature, response.Data.Signature)
	}

	if response.Data.Encoding != "base64" {
		t.Errorf("Expected encoding to be 'base64', got %s", response.Data.Encoding)
	}
}

// Test interface compliance
func TestSolTxRequestInterface(t *testing.T) {
	var _ SolTxRequest = &SolSignTransactionRequest{}
	var _ SolTxRequest = &SolSignAndSendTransactionRequest{}
	var _ SolTxRequest = &SolSignMessageRequest{}
}

// Test type aliases
func TestTypeAliases(t *testing.T) {
	// Test that SolSignAndSendTransactionResponseData is an alias for SolSignTransactionResponseData
	var signData SolSignTransactionResponseData
	var signAndSendData SolSignAndSendTransactionResponseData

	signData = SolSignTransactionResponseData{
		Signature: validSignature,
		Encoding:  "base64",
	}

	signAndSendData = signData

	if signAndSendData.Signature != validSignature {
		t.Errorf("Type alias failed: expected %s, got %s", validSignature, signAndSendData.Signature)
	}

	// Test that SolSignAndSendTransactionResponse is an alias for SolSignTransactionResponse
	var signResponse SolSignTransactionResponse
	var signAndSendResponse SolSignAndSendTransactionResponse

	signResponse = SolSignTransactionResponse{
		Method: "signTransaction",
		Data: SolSignTransactionResponseData{
			Signature: validSignature,
			Encoding:  "base64",
		},
	}

	signAndSendResponse = signResponse

	if signAndSendResponse.Method != "signTransaction" {
		t.Errorf("Type alias failed: expected 'signTransaction', got %s", signAndSendResponse.Method)
	}
}

// Edge case tests
func TestEdgeCases(t *testing.T) {
	t.Run("Empty SolTransaction", func(t *testing.T) {
		tx := &SolTransaction{}
		req := NewSolSignTransactionRequest(tx)

		err := req.ValidateTxRequest()
		if err == nil {
			t.Error("Expected validation to fail for empty transaction")
		}
	})

	t.Run("Nil transaction pointer", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when passing nil transaction to constructor")
			}
		}()
		NewSolSignTransactionRequest(nil)
	})

	t.Run("Very long transaction string", func(t *testing.T) {
		longTx := make([]byte, 10000)
		for i := range longTx {
			longTx[i] = 'A'
		}

		tx := &SolTransaction{
			Transaction: string(longTx),
			Encoding:    "base64",
		}

		req := NewSolSignTransactionRequest(tx)
		err := req.ValidateTxRequest()

		if err != nil {
			t.Errorf("Expected long transaction to be valid, got error: %s", err.Error())
		}
	})
}
