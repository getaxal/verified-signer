package data

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxPersonalSignMessageBytes = 16 * 1024
)

var (
	evmAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	purposePattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// PrivyPersonalSignData is the exact RPC body sent to Privy.
type PrivyPersonalSignData struct {
	Method string `json:"method"`
	Params struct {
		Message  string `json:"message"`
		Encoding string `json:"encoding"`
	} `json:"params"`
}

// AxalEthPersonalSignRequest describes a provider-neutral EIP-191 personal
// message signing request initiated by the Axal backend.
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

func (req *AxalEthPersonalSignRequest) Validate() error {
	if req.Method != "personal_sign" {
		return fmt.Errorf("incorrect signing method")
	}
	if !purposePattern.MatchString(req.Purpose) {
		return fmt.Errorf("purpose must be a lowercase identifier")
	}
	if req.PrivyID == "" {
		return fmt.Errorf("privy_id is required")
	}
	if !evmAddressPattern.MatchString(req.WalletAddress) {
		return fmt.Errorf("wallet_address is not a valid EVM address")
	}
	messageBytes, err := decodePersonalSignMessage(req.Params.Message, req.Params.Encoding)
	if err != nil {
		return err
	}
	if len(messageBytes) == 0 || len(messageBytes) > maxPersonalSignMessageBytes {
		return fmt.Errorf("message length is invalid")
	}
	return nil
}

func decodePersonalSignMessage(message, encoding string) ([]byte, error) {
	switch encoding {
	case "utf-8":
		return []byte(message), nil
	case "hex":
		encoded := strings.TrimPrefix(message, "0x")
		if encoded == "" || len(encoded)%2 != 0 {
			return nil, fmt.Errorf("personal_sign message is not valid hex")
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("personal_sign message is not valid hex")
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("personal_sign encoding must be utf-8 or hex")
	}
}

func (req *AxalEthPersonalSignRequest) GetPrivySignData() PrivyPersonalSignData {
	return PrivyPersonalSignData{Method: req.Method, Params: req.Params}
}

// AuthPayload binds the HMAC to every security-sensitive input while avoiding
// putting the raw message in an HTTP header or log line.
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
