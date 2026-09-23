package data

import (
	"fmt"
	"strings"
)

// Interface for all Eth transaction requests
type EthTxRequest interface {
	ValidateTxRequest() error
	GetMethod() string
	GetPrivySignData() PrivySigningData
}

// This is the signing data sent to privy in the eth_sign method
type PrivySigningData struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
}

// User-initiated signing request (JWT auth only, no privy_id in request)
type UserEthSecp256k1SignRequest struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
	WalletAddress string `json:"wallet_address"`
}

// Axal-initiated signing request (HMAC auth, includes privy_id)
type AxalEthSecp256k1SignRequest struct {
	Method string `json:"method"`
	Params struct {
		Hash string `json:"hash"`
	} `json:"params"`
	PrivyID       string `json:"privy_id"`
	WalletAddress string `json:"wallet_address"`
}

// UserEthSecp256k1SignRequest methods
func (req *UserEthSecp256k1SignRequest) ValidateTxRequest() error {
	if req.Method != "secp256k1_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}
	if req.Params.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	// Required, so a missing field and an empty one are both rejected here and neither
	// can reach the signer as "use whichever wallet you would have picked".
	if !evmAddressPattern.MatchString(req.WalletAddress) {
		return fmt.Errorf("wallet_address is not a valid EVM address")
	}
	return nil
}

func (req *UserEthSecp256k1SignRequest) GetMethod() string {
	return req.Method
}

func (req *UserEthSecp256k1SignRequest) GetPrivySignData() PrivySigningData {
	return PrivySigningData{
		Method: req.Method,
		Params: req.Params,
	}
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
	if !evmAddressPattern.MatchString(req.WalletAddress) {
		return fmt.Errorf("wallet_address is not a valid EVM address")
	}
	return nil
}

// AuthPayload binds the HMAC to the hash, the user, and the wallet that will sign it.
//
// Binding the wallet is the point: without it the address would be unauthenticated, and
// anyone able to modify the body in flight could redirect a signature to another of the
// user's wallets. The address is lower cased so the preimage does not depend on the
// casing the caller happened to send.
func (req *AxalEthSecp256k1SignRequest) AuthPayload() string {
	return strings.Join([]string{
		req.Params.Hash,
		req.PrivyID,
		strings.ToLower(req.WalletAddress),
	}, ":")
}

func (req *AxalEthSecp256k1SignRequest) GetMethod() string {
	return req.Method
}

func (req *AxalEthSecp256k1SignRequest) GetPrivySignData() PrivySigningData {
	return PrivySigningData{
		Method: req.Method,
		Params: req.Params,
	}
}

// Creates a new User secp256k1_sign Request
func NewUserEthSecp256k1SignRequest(hash string, walletAddress string) *UserEthSecp256k1SignRequest {
	return &UserEthSecp256k1SignRequest{
		Method: "secp256k1_sign",
		Params: struct {
			Hash string `json:"hash"`
		}{
			Hash: hash,
		},
		WalletAddress: walletAddress,
	}
}

// Creates a new Axal secp256k1_sign Request
func NewAxalEthSecp256k1SignRequest(hash, privyID, walletAddress string) *AxalEthSecp256k1SignRequest {
	return &AxalEthSecp256k1SignRequest{
		Method: "secp256k1_sign",
		Params: struct {
			Hash string `json:"hash"`
		}{
			Hash: hash,
		},
		PrivyID:       privyID,
		WalletAddress: walletAddress,
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
