package data

import "fmt"

// Interface for all Eth transaction requests
type EthTxRequest interface {
	ValidateTxRequest() error
	GetMethod() string
}

// User-initiated signing request (JWT auth only, no privy_id in request)
type UserEthSecp256k1SignRequest struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
}

// Axal-initiated signing request (JWT + HMAC auth, includes privy_id)
type AxalEthSecp256k1SignRequest struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
	PrivyID string `json:"privy_id"`
}

// UserEthSecp256k1SignRequest methods
func (req *UserEthSecp256k1SignRequest) ValidateTxRequest() error {
	if req.Method != "secp256k1_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}
	if req.Params.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	return nil
}

func (req *UserEthSecp256k1SignRequest) GetMethod() string {
	return req.Method
}

// AxalEthSecp256k1SignRequest methods
func (req *AxalEthSecp256k1SignRequest) ValidateTxRequest() error {
	if req.Method != "secp256k1_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}
	if req.Params.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	if req.PrivyID == "" {
		return fmt.Errorf("privy_id is required for axal requests")
	}
	return nil
}

func (req *AxalEthSecp256k1SignRequest) GetMethod() string {
	return req.Method
}

// Creates a new User secp256k1_sign Request
func NewUserEthSecp256k1SignRequest(hash string) *UserEthSecp256k1SignRequest {
	return &UserEthSecp256k1SignRequest{
		Method: "secp256k1_sign",
		Params: struct {
			Hash string `json:"hash"`
		}{
			Hash: hash,
		},
	}
}

// Creates a new Axal secp256k1_sign Request
func NewAxalEthSecp256k1SignRequest(hash, privyID string) *AxalEthSecp256k1SignRequest {
	return &AxalEthSecp256k1SignRequest{
		Method: "secp256k1_sign",
		Params: struct {
			Hash string `json:"hash"`
		}{
			Hash: hash,
		},
		PrivyID: privyID,
	}
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
