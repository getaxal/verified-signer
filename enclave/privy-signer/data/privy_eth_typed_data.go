package data

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// EIP-712 typed data signing requests. The full typed data JSON (domain, types,
// primaryType, message) is carried verbatim as a string so the enclave hashes it
// itself and can attest to what it signed. The computed digest is cached during
// validation and forwarded to privy via the existing secp256k1_sign method.

// User-initiated EIP-712 signing request (JWT auth only, no privy_id in request)
type UserEthSignTypedDataRequest struct {
	Method string `json:"method"`
	Params struct {
		TypedData string `json:"typed_data"`
	} `json:"params"`

	digest string
}

// Axal-initiated EIP-712 signing request (HMAC auth, includes privy_id)
type AxalEthSignTypedDataRequest struct {
	Method string `json:"method"`
	Params struct {
		TypedData string `json:"typed_data"`
	} `json:"params"`
	PrivyID string `json:"privy_id"`

	digest string
}

// User-initiated EIP-191 personal_sign request (JWT auth only)
type UserEthPersonalSignRequest struct {
	Method string `json:"method"`
	Params struct {
		Message string `json:"message"`
	} `json:"params"`

	digest string
}

// Axal-initiated EIP-191 personal_sign request (HMAC auth, includes privy_id)
type AxalEthPersonalSignRequest struct {
	Method string `json:"method"`
	Params struct {
		Message string `json:"message"`
	} `json:"params"`
	PrivyID string `json:"privy_id"`

	digest string
}

// TypedDataDomainInfo is logged for audit purposes so there is a record of what
// domains/contracts the enclave signed typed data for.
type TypedDataDomainInfo struct {
	Name              string
	VerifyingContract string
	ChainID           string
	PrimaryType       string
}

// hashTypedData parses the EIP-712 typed data JSON and computes the digest
// keccak256(0x1901 || domainSeparator || structHash) in-enclave.
func hashTypedData(typedDataJSON string) (string, *TypedDataDomainInfo, error) {
	if typedDataJSON == "" {
		return "", nil, fmt.Errorf("typed_data is required")
	}

	var typedData apitypes.TypedData
	if err := json.Unmarshal([]byte(typedDataJSON), &typedData); err != nil {
		return "", nil, fmt.Errorf("typed_data is not valid EIP-712 typed data: %w", err)
	}

	if typedData.PrimaryType == "" {
		return "", nil, fmt.Errorf("typed_data is missing primaryType")
	}

	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return "", nil, fmt.Errorf("could not hash typed data: %w", err)
	}

	info := &TypedDataDomainInfo{
		Name:              typedData.Domain.Name,
		VerifyingContract: typedData.Domain.VerifyingContract,
		PrimaryType:       typedData.PrimaryType,
	}
	if typedData.Domain.ChainId != nil {
		info.ChainID = (*big.Int)(typedData.Domain.ChainId).String()
	}

	return hexutil.Encode(hash), info, nil
}

// hashPersonalSignMessage computes the EIP-191 digest
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message) in-enclave.
func hashPersonalSignMessage(message string) (string, error) {
	if message == "" {
		return "", fmt.Errorf("message is required")
	}
	return hexutil.Encode(accounts.TextHash([]byte(message))), nil
}

// UserEthSignTypedDataRequest methods
func (req *UserEthSignTypedDataRequest) ValidateTxRequest() error {
	if req.Method != "eth_signTypedData_v4" {
		return fmt.Errorf("incorrect transaction request method")
	}
	digest, _, err := hashTypedData(req.Params.TypedData)
	if err != nil {
		return err
	}
	req.digest = digest
	return nil
}

func (req *UserEthSignTypedDataRequest) GetMethod() string {
	return req.Method
}

func (req *UserEthSignTypedDataRequest) GetPrivySignData() PrivySigningData {
	return NewUserEthSecp256k1SignRequest(req.digest).GetPrivySignData()
}

func (req *UserEthSignTypedDataRequest) GetDomainInfo() (*TypedDataDomainInfo, error) {
	_, info, err := hashTypedData(req.Params.TypedData)
	return info, err
}

// AxalEthSignTypedDataRequest methods
func (req *AxalEthSignTypedDataRequest) ValidateTxRequest() error {
	if req.Method != "eth_signTypedData_v4" {
		return fmt.Errorf("incorrect transaction request method")
	}
	if req.PrivyID == "" {
		return fmt.Errorf("privy_id is required for axal requests")
	}
	digest, _, err := hashTypedData(req.Params.TypedData)
	if err != nil {
		return err
	}
	req.digest = digest
	return nil
}

func (req *AxalEthSignTypedDataRequest) GetMethod() string {
	return req.Method
}

func (req *AxalEthSignTypedDataRequest) GetPrivySignData() PrivySigningData {
	return NewUserEthSecp256k1SignRequest(req.digest).GetPrivySignData()
}

func (req *AxalEthSignTypedDataRequest) GetDomainInfo() (*TypedDataDomainInfo, error) {
	_, info, err := hashTypedData(req.Params.TypedData)
	return info, err
}

// UserEthPersonalSignRequest methods
func (req *UserEthPersonalSignRequest) ValidateTxRequest() error {
	if req.Method != "personal_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}
	digest, err := hashPersonalSignMessage(req.Params.Message)
	if err != nil {
		return err
	}
	req.digest = digest
	return nil
}

func (req *UserEthPersonalSignRequest) GetMethod() string {
	return req.Method
}

func (req *UserEthPersonalSignRequest) GetPrivySignData() PrivySigningData {
	return NewUserEthSecp256k1SignRequest(req.digest).GetPrivySignData()
}

// AxalEthPersonalSignRequest methods
func (req *AxalEthPersonalSignRequest) ValidateTxRequest() error {
	if req.Method != "personal_sign" {
		return fmt.Errorf("incorrect transaction request method")
	}
	if req.PrivyID == "" {
		return fmt.Errorf("privy_id is required for axal requests")
	}
	digest, err := hashPersonalSignMessage(req.Params.Message)
	if err != nil {
		return err
	}
	req.digest = digest
	return nil
}

func (req *AxalEthPersonalSignRequest) GetMethod() string {
	return req.Method
}

func (req *AxalEthPersonalSignRequest) GetPrivySignData() PrivySigningData {
	return NewUserEthSecp256k1SignRequest(req.digest).GetPrivySignData()
}
