package data

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
func NewSignTransactionRequest(tx *EthTransaction) *EthSignTransactionRequest {
	return &EthSignTransactionRequest{
		Method: "eth_signTransaction",
		Params: struct {
			Transaction EthTransaction `json:"transaction"`
		}{
			Transaction: *tx,
		},
	}
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
func NewSendTransactionRequest(tx *EthTransaction, caip2, chainType string) *EthSendTransactionRequest {
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

type EthPersonalSignRequest struct {
	Method string `json:"method"`
	Params struct {
		Message  string `json:"message"`
		Encoding string `json:"encoding"`
	} `json:"params"`
}

// Creates a new Privy personal_sign Request
func NewPersonalSignRequest(message string) *EthPersonalSignRequest {
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

// EthTransactionSendResponseData represents the data field in the response to the eth_sendTransaction request
type EthSignTransactionResponseData struct {
	Signature string `json:"signature"`
	Encoding  string `json:"encoding"`
}

// EthSendTransactionResponse represents the complete response from the eth_signTransaction and personal_sign request
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
