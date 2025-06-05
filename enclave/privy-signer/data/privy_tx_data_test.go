package data

import (
	"testing"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============= EthSignTransactionRequest Validation Tests =============

func TestEthSignTransactionRequest_ValidateTxRequest_Success(t *testing.T) {
	// Valid request
	req := &EthSignTransactionRequest{
		Method: "eth_signTransaction",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To:    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
				Value: enclave.ToInt64Ptr(1000000000000000000), // 1 ETH
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

func TestEthSignTransactionRequest_ValidateTxRequest_WrongMethod(t *testing.T) {
	req := &EthSignTransactionRequest{
		Method: "eth_sendTransaction", // Wrong method
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}

func TestEthSignTransactionRequest_ValidateTxRequest_EmptyMethod(t *testing.T) {
	req := &EthSignTransactionRequest{
		Method: "", // Empty method
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}

func TestEthSignTransactionRequest_ValidateTxRequest_MissingToField(t *testing.T) {
	req := &EthSignTransactionRequest{
		Method: "eth_signTransaction",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "", // Empty To field
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing to field in the transaction, it is required")
}

func TestEthSignTransactionRequest_ValidateTxRequest_ValidMinimalTransaction(t *testing.T) {
	// Test with only required fields
	req := &EthSignTransactionRequest{
		Method: "eth_signTransaction",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

// ============= EthSendTransactionRequest Validation Tests =============

func TestEthSendTransactionRequest_ValidateTxRequest_Success(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "eth_sendTransaction",
		CAIP2:     "eip155:11155111",
		ChainType: "ethereum",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To:    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
				Value: enclave.ToInt64Ptr(1000000000000000000),
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

func TestEthSendTransactionRequest_ValidateTxRequest_WrongMethod(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "eth_signTransaction", // Wrong method
		CAIP2:     "eip155:11155111",
		ChainType: "ethereum",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}

func TestEthSendTransactionRequest_ValidateTxRequest_EmptyMethod(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "", // Empty method
		CAIP2:     "eip155:11155111",
		ChainType: "ethereum",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}

func TestEthSendTransactionRequest_ValidateTxRequest_MissingToField(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "eth_sendTransaction",
		CAIP2:     "eip155:11155111",
		ChainType: "ethereum",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "", // Empty To field
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing to field in the transaction, it is required")
}

func TestEthSendTransactionRequest_ValidateTxRequest_MissingCAIP2(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "eth_sendTransaction",
		CAIP2:     "", // Empty CAIP2
		ChainType: "ethereum",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing CAIP2 field in the transaction, it is required")
}

func TestEthSendTransactionRequest_ValidateTxRequest_WrongChainType(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "eth_sendTransaction",
		CAIP2:     "eip155:11155111",
		ChainType: "bitcoin", // Wrong chain type
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect chainType field in the transaction, it is required")
}

func TestEthSendTransactionRequest_ValidateTxRequest_EmptyChainType(t *testing.T) {
	req := &EthSendTransactionRequest{
		Method:    "eth_sendTransaction",
		CAIP2:     "eip155:11155111",
		ChainType: "", // Empty chain type
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect chainType field in the transaction, it is required")
}

// ============= EthPersonalSignRequest Validation Tests =============

func TestEthPersonalSignRequest_ValidateTxRequest_Success(t *testing.T) {
	req := &EthPersonalSignRequest{
		Method: "personal_sign",
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  "Hello, World!",
			Encoding: "utf-8",
		},
	}

	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

func TestEthPersonalSignRequest_ValidateTxRequest_WrongMethod(t *testing.T) {
	req := &EthPersonalSignRequest{
		Method: "eth_signTransaction", // Wrong method
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  "Hello, World!",
			Encoding: "utf-8",
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}

func TestEthPersonalSignRequest_ValidateTxRequest_EmptyMethod(t *testing.T) {
	req := &EthPersonalSignRequest{
		Method: "", // Empty method
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  "Hello, World!",
			Encoding: "utf-8",
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}

func TestEthPersonalSignRequest_ValidateTxRequest_MissingMessage(t *testing.T) {
	req := &EthPersonalSignRequest{
		Method: "personal_sign",
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  "", // Empty message
			Encoding: "utf-8",
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing message field in the transaction, it is required")
}

func TestEthPersonalSignRequest_ValidateTxRequest_WrongEncoding(t *testing.T) {
	req := &EthPersonalSignRequest{
		Method: "personal_sign",
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  "Hello, World!",
			Encoding: "ascii", // Wrong encoding
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing encoding field in the transaction, it is required")
}

func TestEthPersonalSignRequest_ValidateTxRequest_EmptyEncoding(t *testing.T) {
	req := &EthPersonalSignRequest{
		Method: "personal_sign",
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  "Hello, World!",
			Encoding: "", // Empty encoding
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing encoding field in the transaction, it is required")
}

// ============= Table-Driven Tests =============

func TestEthSignTransactionRequest_ValidateTxRequest_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		toAddress     string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid_request",
			method:      "eth_signTransaction",
			toAddress:   "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			expectError: false,
		},
		{
			name:          "wrong_method",
			method:        "eth_sendTransaction",
			toAddress:     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			expectError:   true,
			errorContains: "incorrect transaction request method",
		},
		{
			name:          "empty_method",
			method:        "",
			toAddress:     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			expectError:   true,
			errorContains: "incorrect transaction request method",
		},
		{
			name:          "missing_to_address",
			method:        "eth_signTransaction",
			toAddress:     "",
			expectError:   true,
			errorContains: "missing to field in the transaction, it is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EthSignTransactionRequest{
				Method: tt.method,
				Params: struct {
					Transaction EthTransaction `json:"transaction"`
				}{
					Transaction: EthTransaction{
						To: tt.toAddress,
					},
				},
			}

			err := req.ValidateTxRequest()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEthSendTransactionRequest_ValidateTxRequest_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		toAddress     string
		caip2         string
		chainType     string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid_request",
			method:      "eth_sendTransaction",
			toAddress:   "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			caip2:       "eip155:11155111",
			chainType:   "ethereum",
			expectError: false,
		},
		{
			name:          "wrong_method",
			method:        "eth_signTransaction",
			toAddress:     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			caip2:         "eip155:11155111",
			chainType:     "ethereum",
			expectError:   true,
			errorContains: "incorrect transaction request method",
		},
		{
			name:          "missing_to_address",
			method:        "eth_sendTransaction",
			toAddress:     "",
			caip2:         "eip155:11155111",
			chainType:     "ethereum",
			expectError:   true,
			errorContains: "missing to field in the transaction, it is required",
		},
		{
			name:          "missing_caip2",
			method:        "eth_sendTransaction",
			toAddress:     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			caip2:         "",
			chainType:     "ethereum",
			expectError:   true,
			errorContains: "missing CAIP2 field in the transaction, it is required",
		},
		{
			name:          "wrong_chain_type",
			method:        "eth_sendTransaction",
			toAddress:     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			caip2:         "eip155:11155111",
			chainType:     "bitcoin",
			expectError:   true,
			errorContains: "incorrect chainType field in the transaction, it is required",
		},
		{
			name:          "empty_chain_type",
			method:        "eth_sendTransaction",
			toAddress:     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			caip2:         "eip155:11155111",
			chainType:     "",
			expectError:   true,
			errorContains: "incorrect chainType field in the transaction, it is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EthSendTransactionRequest{
				Method:    tt.method,
				CAIP2:     tt.caip2,
				ChainType: tt.chainType,
				Params: struct {
					Transaction EthTransaction `json:"transaction"`
				}{
					Transaction: EthTransaction{
						To: tt.toAddress,
					},
				},
			}

			err := req.ValidateTxRequest()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEthPersonalSignRequest_ValidateTxRequest_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		message       string
		encoding      string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid_request",
			method:      "personal_sign",
			message:     "Hello, World!",
			encoding:    "utf-8",
			expectError: false,
		},
		{
			name:          "wrong_method",
			method:        "eth_signTransaction",
			message:       "Hello, World!",
			encoding:      "utf-8",
			expectError:   true,
			errorContains: "incorrect transaction request method",
		},
		{
			name:          "empty_method",
			method:        "",
			message:       "Hello, World!",
			encoding:      "utf-8",
			expectError:   true,
			errorContains: "incorrect transaction request method",
		},
		{
			name:          "missing_message",
			method:        "personal_sign",
			message:       "",
			encoding:      "utf-8",
			expectError:   true,
			errorContains: "missing message field in the transaction, it is required",
		},
		{
			name:          "wrong_encoding",
			method:        "personal_sign",
			message:       "Hello, World!",
			encoding:      "ascii",
			expectError:   true,
			errorContains: "missing encoding field in the transaction, it is required",
		},
		{
			name:          "empty_encoding",
			method:        "personal_sign",
			message:       "Hello, World!",
			encoding:      "",
			expectError:   true,
			errorContains: "missing encoding field in the transaction, it is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &EthPersonalSignRequest{
				Method: tt.method,
				Params: struct {
					Message  string `json:"message"`
					Encoding string `json:"encoding"`
				}{
					Message:  tt.message,
					Encoding: tt.encoding,
				},
			}

			err := req.ValidateTxRequest()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============= Constructor Function Tests =============

func TestNewSignTransactionRequest(t *testing.T) {
	tx := &EthTransaction{
		To:    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value: enclave.ToInt64Ptr(1000000000000000000),
	}

	req := NewSignTransactionRequest(tx)

	require.NotNil(t, req)
	assert.Equal(t, "eth_signTransaction", req.Method)
	assert.Equal(t, tx.To, req.Params.Transaction.To)
	assert.Equal(t, tx.Value, req.Params.Transaction.Value)

	// Validate the constructed request
	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

func TestNewSendTransactionRequest(t *testing.T) {
	tx := &EthTransaction{
		To:    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value: enclave.ToInt64Ptr(1000000000000000000),
	}
	caip2 := "eip155:11155111"
	chainType := "ethereum"

	req := NewSendTransactionRequest(tx, caip2, chainType)

	require.NotNil(t, req)
	assert.Equal(t, "eth_sendTransaction", req.Method)
	assert.Equal(t, caip2, req.CAIP2)
	assert.Equal(t, chainType, req.ChainType)
	assert.Equal(t, tx.To, req.Params.Transaction.To)
	assert.Equal(t, tx.Value, req.Params.Transaction.Value)

	// Validate the constructed request
	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

func TestNewPersonalSignRequest(t *testing.T) {
	message := "Hello, World!"

	req := NewPersonalSignRequest(message)

	require.NotNil(t, req)
	assert.Equal(t, "personal_sign", req.Method)
	assert.Equal(t, message, req.Params.Message)
	assert.Equal(t, "utf-8", req.Params.Encoding)

	// Validate the constructed request
	err := req.ValidateTxRequest()
	assert.NoError(t, err)
}

// ============= Interface Method Tests =============

func TestEthSignTransactionRequest_GetMethod(t *testing.T) {
	req := &EthSignTransactionRequest{Method: "eth_signTransaction"}
	assert.Equal(t, "eth_signTransaction", req.GetMethod())
}

func TestEthSignTransactionRequest_GetTransaction(t *testing.T) {
	tx := EthTransaction{
		To:    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value: enclave.ToInt64Ptr(1000000000000000000),
	}
	req := &EthSignTransactionRequest{
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{Transaction: tx},
	}

	result := req.GetTransaction()
	require.NotNil(t, result)
	assert.Equal(t, tx.To, result.To)
	assert.Equal(t, tx.Value, result.Value)
}

func TestEthSendTransactionRequest_GetMethod(t *testing.T) {
	req := &EthSendTransactionRequest{Method: "eth_sendTransaction"}
	assert.Equal(t, "eth_sendTransaction", req.GetMethod())
}

func TestEthSendTransactionRequest_GetTransaction(t *testing.T) {
	tx := EthTransaction{
		To:    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value: enclave.ToInt64Ptr(1000000000000000000),
	}
	req := &EthSendTransactionRequest{
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{Transaction: tx},
	}

	result := req.GetTransaction()
	require.NotNil(t, result)
	assert.Equal(t, tx.To, result.To)
	assert.Equal(t, tx.Value, result.Value)
}

func TestEthPersonalSignRequest_GetMethod(t *testing.T) {
	req := &EthPersonalSignRequest{Method: "personal_sign"}
	assert.Equal(t, "personal_sign", req.GetMethod())
}

func TestEthPersonalSignRequest_GetTransaction(t *testing.T) {
	req := &EthPersonalSignRequest{}
	result := req.GetTransaction()
	assert.Nil(t, result)
}

// ============= Edge Cases and Complex Scenarios =============

func TestValidation_WithComplexTransactionData(t *testing.T) {
	// Test with all transaction fields populated
	tx := &EthTransaction{
		ChainID:              enclave.ToInt64Ptr(11155111),
		Data:                 "0x1234567890abcdef",
		From:                 "0x742d35Cc6E7c8D2a3C8d65C5c8c5c8c5c8c5c8c5",
		GasLimit:             enclave.ToInt64Ptr(50000),
		GasPrice:             enclave.ToInt64Ptr(20000000000),
		MaxFeePerGas:         enclave.ToInt64Ptr(1000308),
		MaxPriorityFeePerGas: enclave.ToInt64Ptr(1000000),
		Nonce:                enclave.ToInt64Ptr(0),
		To:                   "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Type:                 enclave.ToInt64Ptr(2),
		Value:                enclave.ToInt64Ptr(1000000000000000000),
	}

	signReq := NewSignTransactionRequest(tx)
	err := signReq.ValidateTxRequest()
	assert.NoError(t, err)

	sendReq := NewSendTransactionRequest(tx, "eip155:11155111", "ethereum")
	err = sendReq.ValidateTxRequest()
	assert.NoError(t, err)
}

func TestValidation_MultipleErrors(t *testing.T) {
	// Test that validation stops at first error
	req := &EthSendTransactionRequest{
		Method:    "wrong_method",
		CAIP2:     "",        // Also wrong
		ChainType: "bitcoin", // Also wrong
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: EthTransaction{
				To: "", // Also wrong
			},
		},
	}

	err := req.ValidateTxRequest()
	assert.Error(t, err)
	// Should get the first validation error (method)
	assert.Contains(t, err.Error(), "incorrect transaction request method")
}
