package data

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	crossmintchallenge "github.com/getaxal/verified-signer/enclave/privy-signer/challenges/crossmint"
)

const (
	CrossmintWalletOwnershipPurpose = "crossmint_wallet_ownership"
	maxPersonalSignMessageBytes     = 16 * 1024
)

var evmAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// PrivyPersonalSignData is the exact RPC body sent to Privy.
type PrivyPersonalSignData struct {
	Method string `json:"method"`
	Params struct {
		Message  string `json:"message"`
		Encoding string `json:"encoding"`
	} `json:"params"`
}

// AxalEthPersonalSignRequest is intentionally limited to Crossmint wallet
// ownership challenges. It is not a general-purpose backend signing API.
type AxalEthPersonalSignRequest struct {
	Method string `json:"method"`
	Params struct {
		Message  string `json:"message"`
		Encoding string `json:"encoding"`
	} `json:"params"`
	PrivyID       string `json:"privy_id"`
	WalletAddress string `json:"wallet_address"`
	Purpose       string `json:"purpose"`
}

type PersonalSignResponseData struct {
	Signature string `json:"signature"`
	Encoding  string `json:"encoding"`
}

type PersonalSignResponse struct {
	Method string                   `json:"method"`
	Data   PersonalSignResponseData `json:"data"`
}

func (req *AxalEthPersonalSignRequest) Validate(now time.Time) error {
	if req.Method != "personal_sign" {
		return fmt.Errorf("incorrect signing method")
	}
	if req.Purpose != CrossmintWalletOwnershipPurpose {
		return fmt.Errorf("unsupported signing purpose")
	}
	if req.Params.Encoding != "utf-8" {
		return fmt.Errorf("personal_sign encoding must be utf-8")
	}
	if req.PrivyID == "" {
		return fmt.Errorf("privy_id is required")
	}
	if !evmAddressPattern.MatchString(req.WalletAddress) {
		return fmt.Errorf("wallet_address is not a valid EVM address")
	}
	if len(req.Params.Message) == 0 || len(req.Params.Message) > maxPersonalSignMessageBytes {
		return fmt.Errorf("message length is invalid")
	}
	return crossmintchallenge.ValidateOwnership(req.Params.Message, req.WalletAddress, now)
}

func (req *AxalEthPersonalSignRequest) GetPrivySignData() PrivyPersonalSignData {
	return PrivyPersonalSignData{Method: req.Method, Params: req.Params}
}

// AuthPayload binds the HMAC to every security-sensitive input while avoiding
// putting the raw multiline challenge in an HTTP header or log line.
func (req *AxalEthPersonalSignRequest) AuthPayload() string {
	digest := sha256.Sum256([]byte(req.Params.Message))
	return strings.Join([]string{
		req.Method,
		req.Purpose,
		req.Params.Encoding,
		strings.ToLower(req.WalletAddress),
		hex.EncodeToString(digest[:]),
		req.PrivyID,
	}, ":")
}
