package data

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// LinkedAccount represents different types of linked accounts (email, wallet, etc.)
type LinkedAccount struct {
	// Common fields for all account types
	WalletID         string `json:"id,omitempty"`
	Type             string `json:"type"`
	VerifiedAt       int64  `json:"verified_at"`
	FirstVerifiedAt  int64  `json:"first_verified_at"`
	LatestVerifiedAt int64  `json:"latest_verified_at"`

	// Email-specific fields
	Address string `json:"address,omitempty"`

	// Wallet-specific fields
	WalletIndex      int    `json:"wallet_index"`
	ChainID          string `json:"chain_id,omitempty"`
	ChainType        string `json:"chain_type,omitempty"`
	Delegated        bool   `json:"delegated"`
	WalletClient     string `json:"wallet_client,omitempty"`
	WalletClientType string `json:"wallet_client_type,omitempty"`
	ConnectorType    string `json:"connector_type,omitempty"`
	Imported         bool   `json:"imported,omitempty"`
	RecoveryMethod   string `json:"recovery_method,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
	ExternalID       string `json:"external_id,omitempty"`
}

// PrivyUser represents the main user object from Privy API
type PrivyUser struct {
	PrivyID          string          `json:"id"`
	CreatedAt        int64           `json:"created_at"`
	LinkedAccounts   []LinkedAccount `json:"linked_accounts"`
	MFAMethods       []interface{}   `json:"mfa_methods"`
	HasAcceptedTerms bool            `json:"has_accepted_terms"`
	IsGuest          bool            `json:"is_guest"`
}

// Fetches the users Eth delegated wallet, this is a wallet that simply is both an ethereum wallet as well as a delegated wallet
func (pu *PrivyUser) GetUsersEthDelegatedWallet() *LinkedAccount {
	for _, acc := range pu.LinkedAccounts {
		if acc.Delegated && acc.ChainType == "ethereum" {
			return &acc
		}
	}

	return nil
}

// Fetches the users delegated eth wallet at a specific address, or nil if the user does
// not hold one. Address comparison is case insensitive.
//
// A user may hold several delegated eth wallets, so signing requests name the one they
// want and we resolve it here. The delegated/chain_type filter is load bearing rather
// than defensive: LinkedAccount.Address carries email addresses as well as wallet
// addresses, so matching on the address alone would let a non wallet account satisfy
// the lookup.
func (pu *PrivyUser) GetEthDelegatedWalletByAddress(address string) *LinkedAccount {
	if address == "" {
		return nil
	}

	for _, acc := range pu.LinkedAccounts {
		if acc.Delegated && acc.ChainType == "ethereum" && strings.EqualFold(acc.Address, address) {
			return &acc
		}
	}

	return nil
}

// Fetches the users delegated eth wallet carrying a given Privy external id, or nil.
//
// This is how a purpose-built wallet is recognised on a repeat provisioning request, so
// that asking twice returns the wallet the user already has instead of minting a second
// one they could split funds across.
func (pu *PrivyUser) GetEthDelegatedWalletByExternalID(externalID string) *LinkedAccount {
	if externalID == "" {
		return nil
	}

	for _, acc := range pu.LinkedAccounts {
		if acc.Delegated && acc.ChainType == "ethereum" && acc.ExternalID == externalID {
			return &acc
		}
	}

	return nil
}

// Fetches the users sol delegated wallet, this is a wallet that simply is both an solana wallet as well as a delegated wallet
func (pu *PrivyUser) GetUsersSolDelegatedWallet() *LinkedAccount {
	for _, acc := range pu.LinkedAccounts {
		if acc.Delegated && acc.ChainType == "solana" {
			return &acc
		}
	}

	return nil
}

// UnixTime is a custom type that can unmarshal Unix timestamps from JSON
type UnixTime struct {
	time.Time
}

// UnmarshalJSON implements custom unmarshaling for Unix timestamps
func (ut *UnixTime) UnmarshalJSON(data []byte) error {
	// Handle null values
	if string(data) == "null" {
		return nil
	}

	// Try to parse as Unix timestamp (number)
	if len(data) > 0 && data[0] != '"' {
		// It's a number, parse as Unix timestamp
		timestamp, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return err
		}
		ut.Time = time.Unix(timestamp, 0)
		return nil
	}

	// Try to parse as RFC3339 string (quoted)
	var timeStr string
	if err := json.Unmarshal(data, &timeStr); err != nil {
		return err
	}

	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return err
	}

	ut.Time = parsedTime
	return nil
}

// CreateWalletRequest represents the request to create wallets for an existing user
type CreateWalletRequest struct {
	PrivyWalletCreateRequestWallets []*CreateWalletData `json:"wallets"`
}

// CreateWalletData represents the configuration for creating a single wallet
type CreateWalletData struct {
	ChainType         string              `json:"chain_type"` // ethereum, solana, etc.
	CreateSmartWallet bool                `json:"create_smart_wallet,omitempty"`
	AdditionalSigners []*AdditionalSigner `json:"additional_signers,omitempty"`
	ExternalID        string              `json:"external_id,omitempty"`
}

// AdditionalSigner represents additional signers for wallet creation
type AdditionalSigner struct {
	SignerID          string   `json:"signer_id"`
	OverridePolicyIDs []string `json:"override_policy_ids,omitempty"`
}

func NewCreateEthWalletRequest(delegatedSignerId string) *CreateWalletRequest {
	return NewCreateEthWalletRequestWithExternalID(delegatedSignerId, "")
}

// Creates an eth wallet create request carrying a Privy external id.
//
// The external id is what makes a purpose-built wallet addressable and findable later. It
// is also our outermost duplicate guard: Privy documents external ids as unique per app,
// so a second create under the same id collides there rather than quietly producing a
// second funded address.
func NewCreateEthWalletRequestWithExternalID(delegatedSignerId string, externalID string) *CreateWalletRequest {
	return &CreateWalletRequest{
		PrivyWalletCreateRequestWallets: []*CreateWalletData{
			{
				ChainType: "ethereum",
				AdditionalSigners: []*AdditionalSigner{
					{
						SignerID: delegatedSignerId,
					},
				},
				ExternalID: externalID,
			},
		},
	}
}

// CreateWalletResponse represents the response for creating a single wallet
type CreateWalletResponse struct {
	ID             string           `json:"id"`
	CreatedAt      UnixTime         `json:"created_at"`
	LinkedAccounts []*LinkedAccount `json:"linked_accounts"`
	CustomMetadata interface{}      `json:"custom_metadata,omitempty"`
}
