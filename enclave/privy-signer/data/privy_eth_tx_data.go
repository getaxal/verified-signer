package data

import "fmt"

// Common transaction structure used in both APIs
type EthTransaction struct {
	ChainID              *int64 `json:"chain_id,omitempty"`
	Data                 string `json:"data,omitempty"`
	From                 string `json:"from,omitempty"`
	GasLimit             *int64 `json:"gas_limit,omitempty"`
	GasPrice             *int64 `json:"gas_price,omitempty"`
	MaxFeePerGas         *int64 `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas *int64 `json:"max_priority_fee_per_gas,omitempty"`
	Nonce                *int64 `json:"nonce,omitempty"`
	To                   string `json:"to"`
	Type                 *int64 `json:"type,omitempty"` // Available options: 0, 1, 2
	Value                *int64 `json:"value,omitempty"`
}

// Interface for all Eth transaction requests
type EthTxRequest interface {
	ValidateTxRequest() error
	GetMethod() string
	GetTransaction() *EthTransaction
}

// Request struct for eth_signTransaction
// Example would be:
//
//	{
//		"method": "eth_signTransaction",
//		"params": {
//			"transaction": {
//			"to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
//			"value": "0x2386F26FC10000",
//			"chain_id": 11155111,
//			"data": "0x",
//			"gas_limit": 50000,
//			"nonce": 0,
//			"max_fee_per_gas": 1000308,
//			"max_priority_fee_per_gas": "1000000"
//			}
//		}
//	}
type EthSignTransactionRequest struct {
	Method string `json:"method"`
	Params struct {
		Transaction EthTransaction `json:"transaction"`
	} `json:"params"`
}

// Creates a new Privy eth_signTransaction Request
func NewEthSignTransactionRequest(tx *EthTransaction) *EthSignTransactionRequest {
	return &EthSignTransactionRequest{
		Method: "eth_signTransaction",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: *tx,
		},
	}
}

func (req *EthSignTransactionRequest) ValidateTxRequest() error {
	if req.Method != "eth_signTransaction" {
		return fmt.Errorf("incorrect transaction request method")
	}

	if req.Params.Transaction.To == "" {
		return fmt.Errorf("missing to field in the transaction, it is required")
	}

	return nil
}

func (req *EthSignTransactionRequest) GetTransaction() *EthTransaction {
	return &req.Params.Transaction
}

func (req *EthSignTransactionRequest) GetMethod() string {
	return req.Method
}

// Request struct for eth_sendTransaction
// Example would be:
//
//	{
//		"method": "eth_sendTransaction",
//		"caip2": "eip155:11155111",
//		"chain_type": "ethereum",
//		"params": {
//		  "transaction": {
//			"to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
//			"value": "0x2386F26FC10000",
//		  }
//		}
//	  }
type EthSendTransactionRequest struct {
	CAIP2     string `json:"caip2"`
	ChainType string `json:"chain_type"`
	Method    string `json:"method"`
	Params    struct {
		Transaction EthTransaction `json:"transaction"`
	} `json:"params"`
}

// Creates a new Privy eth_sendTransaction Request
func NewEthSendTransactionRequest(tx *EthTransaction, caip2, chainType string) *EthSendTransactionRequest {
	return &EthSendTransactionRequest{
		Method:    "eth_sendTransaction",
		CAIP2:     caip2,
		ChainType: chainType,
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: *tx,
		},
	}
}

func (req *EthSendTransactionRequest) ValidateTxRequest() error {
	if req.Method != "eth_sendTransaction" {
		return fmt.Errorf("incorrect transaction request method")
	}

	if req.Params.Transaction.To == "" {
		return fmt.Errorf("missing to field in the transaction, it is required")
	}

	if req.CAIP2 == "" {
		return fmt.Errorf("missing CAIP2 field in the transaction, it is required")
	}

	if req.ChainType != "ethereum" {
		return fmt.Errorf("incorrect chainType field in the transaction, it is required")
	}

	return nil
}

func (req *EthSendTransactionRequest) GetTransaction() *EthTransaction {
	return &req.Params.Transaction
}

func (req *EthSendTransactionRequest) GetMethod() string {
	return req.Method
}

type EthPersonalSignRequest struct {
	Method string `json:"method"`
	Params struct {
		Message  string `json:"message"`
		Encoding string `json:"encoding"`
	} `json:"params"`
}

// Creates a new Privy personal_sign Request
func NewEthPersonalSignRequest(message string) *EthPersonalSignRequest {
	return &EthPersonalSignRequest{
		Method: "personal_sign",
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  message,
			Encoding: "utf-8",
		},
	}
}

func (req *EthPersonalSignRequest) ValidateTxRequest() error {
	if req.Method != "personal_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}

	if req.Params.Message == "" {
		return fmt.Errorf("missing message field in the transaction, it is required")
	}

	if req.Params.Encoding != "utf-8" {
		return fmt.Errorf("missing encoding field in the transaction, it is required")
	}

	return nil
}

func (req *EthPersonalSignRequest) GetTransaction() *EthTransaction {
	return nil
}

func (req *EthPersonalSignRequest) GetMethod() string {
	return req.Method
}

type EthSecp256k1SignRequest struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
}

// Creates a new Privy secp256k1_sign Request
func NewEthSecp256k1SignRequest(hash string) *EthSecp256k1SignRequest {
	return &EthSecp256k1SignRequest{
		Method: "secp256k1_sign",
		Params: struct {
			Hash string `json:"hash"`
		}{
			Hash: hash,
		},
	}
}

func (req *EthSecp256k1SignRequest) ValidateTxRequest() error {
	if req.Method != "secp256k1_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}

	return nil
}

func (req *EthSecp256k1SignRequest) GetTransaction() *EthTransaction {
	return nil
}

func (req *EthSecp256k1SignRequest) GetMethod() string {
	return req.Method
}

// EthSignTransactionResponseData represents the data field in the response to the eth_signTransaction request
type EthSignTransactionResponseData struct {
	Signature string `json:"signed_transaction"`
	Encoding  string `json:"encoding"`
}

// EthSignTransactionResponse represents the complete response from the eth_signTransaction request
type EthSignTransactionResponse struct {
	Method string                         `json:"method"`
	Data   EthSignTransactionResponseData `json:"data"`
}

// EthTransactionSendResponseData represents the data field in the response to the eth_sendTransaction request
type EthSendTransactionResponseData struct {
	Hash          string `json:"hash"`
	CAIP2         string `json:"caip2"`
	TransactionID string `json:"transaction_id"`
}

// EthSendTransactionResponse represents the complete response from the eth_sendTransaction request
type EthSendTransactionResponse struct {
	Method string                         `json:"method"`
	Data   EthSendTransactionResponseData `json:"data"`
}

// EthPersonalSignResponseData represents the data field in the response to the personalSign request
type EthPersonalSignResponseData struct {
	Signature string `json:"signature"`
	Encoding  string `json:"encoding"`
}

// EthPersonalSignResponse represents the complete response from the personalSign request
type EthPersonalSignResponse struct {
	Method string                      `json:"method"`
	Data   EthPersonalSignResponseData `json:"data"`
}

// EthSecp256k1SignResponseData represents the data field in the response to the secp256k1_sign request
type EthSecp256k1SignResponseData struct {
	Signature string `json:"signature"`
	Encoding  string `json:"encoding"`
}

// EthSecp256k1SignResponse represents the complete response from the secp256k1_sign request
type EthSecp256k1SignResponse struct {
	Method string                       `json:"method"`
	Data   EthSecp256k1SignResponseData `json:"data"`
}
