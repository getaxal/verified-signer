package data

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	// Privy's RPC method for signing a Solana transaction without broadcasting it.
	solSignTransactionMethod = "signTransaction"

	// The only encoding Privy accepts for a Solana transaction.
	solTransactionEncoding = "base64"

	// Solana caps a serialized transaction at 1232 bytes today. The bound here is looser so
	// that a raise of the network's limit does not need an enclave release, which changes the
	// attested measurements. It exists to refuse garbage before it reaches Privy, not to
	// enforce the network's limit.
	maxSolTransactionBytes = 4096
)

// A Solana address is a base58-encoded ed25519 public key: 32 bytes, which is 32 to 44
// characters of an alphabet that omits 0, O, I and l. The pattern checks the shape, not the
// decoded length — an address that passes it and is not one of the user's wallets is refused
// by the ownership check, which is the check that matters.
var solAddressPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)

// SolSignTransactionParams carries the transaction to sign, as Privy's RPC takes it.
type SolSignTransactionParams struct {
	Transaction string `json:"transaction"`
	Encoding    string `json:"encoding"`
}

// PrivySolSignTransactionData is the exact RPC body sent to Privy.
type PrivySolSignTransactionData struct {
	Method string                   `json:"method"`
	Params SolSignTransactionParams `json:"params"`
}

// User-initiated Solana signing request (JWT auth only, no privy_id in request)
type UserSolSignTransactionRequest struct {
	Method        string                   `json:"method"`
	Params        SolSignTransactionParams `json:"params"`
	WalletAddress string                   `json:"wallet_address"`
}

// Axal-initiated Solana signing request (HMAC auth, includes privy_id)
type AxalSolSignTransactionRequest struct {
	Method        string                   `json:"method"`
	Params        SolSignTransactionParams `json:"params"`
	PrivyID       string                   `json:"privy_id"`
	WalletAddress string                   `json:"wallet_address"`
}

// SolSignTransactionResponseData represents the data field in the response to signTransaction
type SolSignTransactionResponseData struct {
	SignedTransaction string `json:"signed_transaction"`
	Encoding          string `json:"encoding"`
}

// SolSignTransactionResponse represents the complete response from the signTransaction request
type SolSignTransactionResponse struct {
	Method string                         `json:"method"`
	Data   SolSignTransactionResponseData `json:"data"`
}

// The checks the two request types share. The wallet address is required for the same reason
// it is on the eth routes: a missing one must not reach the signer as "use whichever wallet
// you would have picked".
func validateSolSignTransaction(method string, params SolSignTransactionParams, walletAddress string) error {
	if method != solSignTransactionMethod {
		return fmt.Errorf("incorrect transaction request method")
	}
	if params.Encoding != solTransactionEncoding {
		return fmt.Errorf("encoding must be base64")
	}

	transaction, err := base64.StdEncoding.DecodeString(params.Transaction)
	if err != nil {
		return fmt.Errorf("transaction is not valid base64")
	}
	if len(transaction) == 0 || len(transaction) > maxSolTransactionBytes {
		return fmt.Errorf("transaction length is invalid")
	}

	if !solAddressPattern.MatchString(walletAddress) {
		return fmt.Errorf("wallet_address is not a valid Solana address")
	}

	return nil
}

// UserSolSignTransactionRequest methods
func (req *UserSolSignTransactionRequest) ValidateTxRequest() error {
	return validateSolSignTransaction(req.Method, req.Params, req.WalletAddress)
}

func (req *UserSolSignTransactionRequest) GetMethod() string {
	return req.Method
}

func (req *UserSolSignTransactionRequest) GetPrivySignData() PrivySolSignTransactionData {
	return PrivySolSignTransactionData{Method: req.Method, Params: req.Params}
}

// AxalSolSignTransactionRequest methods
func (req *AxalSolSignTransactionRequest) ValidateTxRequest() error {
	if req.PrivyID == "" {
		return fmt.Errorf("privy_id is required for axal requests")
	}

	return validateSolSignTransaction(req.Method, req.Params, req.WalletAddress)
}

func (req *AxalSolSignTransactionRequest) GetMethod() string {
	return req.Method
}

func (req *AxalSolSignTransactionRequest) GetPrivySignData() PrivySolSignTransactionData {
	return PrivySolSignTransactionData{Method: req.Method, Params: req.Params}
}

// AuthPayload binds the HMAC to the transaction, the user, and the wallet that will sign it.
//
// Two things differ from the eth preimages, both deliberately:
//
//   - The wallet address is NOT lower cased. A Solana address is base58, where case is part of
//     the value, so folding it would make two different keys share a preimage.
//   - It opens with the chain. "signTransaction" does not name a chain on its own, and the
//     prefix keeps a signature computed for this route from ever validating on another.
//
// The transaction is hashed rather than included, as the personal-sign message is, so the
// preimage stays short and nothing signable reaches a log line. The digest is over the base64
// string exactly as sent, so the caller hashes the same bytes it puts on the wire.
//
// The Privy id goes last because it is the one field that contains the separator.
func (req *AxalSolSignTransactionRequest) AuthPayload() string {
	digest := sha256.Sum256([]byte(req.Params.Transaction))
	return strings.Join([]string{
		ChainTypeSolana,
		req.Method,
		req.Params.Encoding,
		req.WalletAddress,
		hex.EncodeToString(digest[:]),
		req.PrivyID,
	}, ":")
}

// Creates a new User signTransaction Request
func NewUserSolSignTransactionRequest(transaction string, walletAddress string) *UserSolSignTransactionRequest {
	return &UserSolSignTransactionRequest{
		Method:        solSignTransactionMethod,
		Params:        SolSignTransactionParams{Transaction: transaction, Encoding: solTransactionEncoding},
		WalletAddress: walletAddress,
	}
}

// Creates a new Axal signTransaction Request
func NewAxalSolSignTransactionRequest(transaction, privyID, walletAddress string) *AxalSolSignTransactionRequest {
	return &AxalSolSignTransactionRequest{
		Method:        solSignTransactionMethod,
		Params:        SolSignTransactionParams{Transaction: transaction, Encoding: solTransactionEncoding},
		PrivyID:       privyID,
		WalletAddress: walletAddress,
	}
}
