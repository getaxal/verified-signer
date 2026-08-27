package data

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
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
	return validateCrossmintChallenge(req.Params.Message, req.WalletAddress, now)
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

func validateCrossmintChallenge(message, walletAddress string, now time.Time) error {
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	if len(lines) < 8 || strings.TrimSpace(lines[0]) != "crossmint.com wants you to sign in with your blockchain account:" {
		return fmt.Errorf("message is not a Crossmint CAIP-122 challenge")
	}

	challengeAddress := strings.TrimSpace(lines[1])
	if !strings.EqualFold(challengeAddress, walletAddress) {
		return fmt.Errorf("challenge wallet does not match requested wallet")
	}

	fields := make(map[string]string)
	for _, line := range lines[2:] {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, ":")
		if found {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	if fields["Version"] != "1" || fields["Nonce"] == "" || fields["Request ID"] == "" {
		return fmt.Errorf("challenge is missing required CAIP-122 fields")
	}
	uri, err := url.Parse(fields["URI"])
	if err != nil || uri.Scheme != "https" || (uri.Hostname() != "crossmint.com" && !strings.HasSuffix(uri.Hostname(), ".crossmint.com")) {
		return fmt.Errorf("challenge URI is not controlled by Crossmint")
	}
	if !isAllowedCrossmintChain(fields["Chain ID"]) {
		return fmt.Errorf("challenge chain is not allowed")
	}

	issuedAt, err := time.Parse(time.RFC3339, fields["Issued At"])
	if err != nil || issuedAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("challenge issued-at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, fields["Expiration Time"])
	if err != nil || !expiresAt.After(now) || !expiresAt.After(issuedAt) {
		return fmt.Errorf("challenge expiration is invalid")
	}

	return nil
}

func isAllowedCrossmintChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "base", "base-sepolia", "eip155:8453", "eip155:84532":
		return true
	default:
		return false
	}
}
