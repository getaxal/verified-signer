package data

import "fmt"

// Common transaction structure used in the sol transactions
type SolTransaction struct {
	Transaction string `json:"transaction"`
	Encoding    string `json:"encoding"`
}

// Interface for all Sol transaction requests
type SolTxRequest interface {
	ValidateTxRequest() error
	GetMethod() string
	GetTransaction() *SolTransaction
}

// Request struct for Solana signTransaction request
// Example would be:
//
//	{
//	  "method": "signTransaction",
//	  "params": {
//	    "transaction": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDRpb0mdmKftapwzzqUtlcDnuWbw8vwlyiyuWyyieQFKESezu52HWNss0SAcb60ftz7DSpgTwUmfUSl1CYHJ91GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAScgJ7J0AXFr1azCEvB1Y5zpiF4eXR+yTW0UB7am+E/MBAgIAAQwCAAAAQEIPAAAAAAA=",
//	    "encoding": "base64"
//	  }
//	}
type SolSignTransactionRequest struct {
	Method      string         `json:"method"`
	Transaction SolTransaction `json:"params"`
}

// Creates a new Privy Solana signTransaction Request
func NewSolSignTransactionRequest(tx *SolTransaction) *SolSignTransactionRequest {
	return &SolSignTransactionRequest{
		Method:      "signTransaction",
		Transaction: *tx,
	}
}

func (req *SolSignTransactionRequest) ValidateTxRequest() error {
	if req.Method != "signTransaction" {
		return fmt.Errorf("incorrect transaction request method")
	}

	if req.Transaction.Transaction == "" {
		return fmt.Errorf("missing transaction data, it is required")
	}

	if req.Transaction.Encoding != "base64" {
		return fmt.Errorf("Inavid encoding format, only base64 accepted")
	}

	return nil
}

func (req *SolSignTransactionRequest) GetTransaction() *SolTransaction {
	return &req.Transaction
}

func (req *SolSignTransactionRequest) GetMethod() string {
	return req.Method
}

// Request struct for Solana signAndSend transaction
// Example would be:
//
//	{
//		"method": "signAndSendTransaction",
//		"caip2": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
//		"params": {
//			"transaction": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAEDRpb0mdmKftapwzzqUtlcDnuWbw8vwlyiyuWyyieQFKESezu52HWNss0SAcb60ftz7DSpgTwUmfUSl1CYHJ91GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAScgJ7J0AXFr1azCEvB1Y5zpiF4eXR+yTW0UB7am+E/MBAgIAAQwCAAAAQEIPAAAAAAA=",
//		    "encoding": "base64"
//		 }
//	}
type SolSignAndSendTransactionRequest struct {
	CAIP2       string         `json:"caip2"`
	Method      string         `json:"method"`
	Transaction SolTransaction `json:"params"`
}

// Creates a new Privy eth_sendTransaction Request
func NewSolSignAndSendTransactionRequest(tx *SolTransaction, caip2 string) *SolSignAndSendTransactionRequest {
	return &SolSignAndSendTransactionRequest{
		Method:      "signAndSendTransaction",
		CAIP2:       caip2,
		Transaction: *tx,
	}
}

func (req *SolSignAndSendTransactionRequest) ValidateTxRequest() error {
	if req.Method != "signAndSendTransaction" {
		return fmt.Errorf("incorrect transaction request method")
	}

	if req.Transaction.Transaction == "" {
		return fmt.Errorf("missing transaction data, it is required")
	}

	if req.CAIP2 == "" {
		return fmt.Errorf("missing CAIP2 field in the transaction, it is required")
	}

	if req.Transaction.Encoding != "base64" {
		return fmt.Errorf("Inavid encoding format, only base64 accepted")
	}

	return nil
}

func (req *SolSignAndSendTransactionRequest) GetTransaction() *SolTransaction {
	return &req.Transaction
}

func (req *SolSignAndSendTransactionRequest) GetMethod() string {
	return req.Method
}

type SolSignMessageRequest struct {
	Method string `json:"method"`
	Params struct {
		Message  string `json:"message"`
		Encoding string `json:"encoding"`
	} `json:"params"`
}

// Creates a new Solana signMessage request
func NewSolSignMessageRequest(message string) *SolSignMessageRequest {
	return &SolSignMessageRequest{
		Method: "signMessage",
		Params: struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
		}{
			Message:  message,
			Encoding: "base64",
		},
	}
}

func (req *SolSignMessageRequest) ValidateTxRequest() error {
	if req.Method != "signMessage" {
		return fmt.Errorf("incorrect transaction request method")
	}

	if req.Params.Message == "" {
		return fmt.Errorf("missing message field in the transaction, it is required")
	}

	if req.Params.Encoding != "base64" {
		return fmt.Errorf("Inavid encoding format, only base64 accepted")
	}

	return nil
}

func (req *SolSignMessageRequest) GetTransaction() *SolTransaction {
	return nil
}

func (req *SolSignMessageRequest) GetMethod() string {
	return req.Method
}

// SolTransactionSignResponseData represents the data field in the response to the solana signTransaction request
type SolSignTransactionResponseData struct {
	Signature string `json:"signed_transaction"`
	Encoding  string `json:"encoding"`
}

// SolSignTransactionResponse represents the complete response from the Solana signTransaction request
type SolSignTransactionResponse struct {
	Method string                         `json:"method"`
	Data   SolSignTransactionResponseData `json:"data"`
}

// SolSignAndSendTransactionResponseData represents the data field in the response to the Solana signAndSendTransaction request (same as signTransaction)
type SolSignAndSendTransactionResponseData = SolSignTransactionResponseData

// SolSignAndSendTransactionResponseData represents the complete response from the Solana signAndSendTransaction request (same as signTransaction)
type SolSignAndSendTransactionResponse = SolSignTransactionResponse

// SolSignMessageResponseData represents the data field in the response to the signMessage request
type SolSignMessageResponseData struct {
	Signature string `json:"signature"`
	Encoding  string `json:"encoding"`
}

// SolSignMessageResponse represents the complete response from the signMessage request
type SolSignMessageResponse struct {
	Method string                     `json:"method"`
	Data   SolSignMessageResponseData `json:"data"`
}
