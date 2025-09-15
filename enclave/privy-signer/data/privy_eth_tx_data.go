package data

import "fmt"

// Interface for all Eth transaction requests
type EthTxRequest interface {
	ValidateTxRequest() error
	GetMethod() string
}

type EthSecp256k1SignRequest struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
	SigningType string `json:"signing_type"`
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

func (req *EthSecp256k1SignRequest) GetMethod() string {
	return req.Method
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
