package data

import (
	"encoding/json"
	"strconv"
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
	WalletIndex      int    `json:"wallet_index,omitempty"`
	ChainID          string `json:"chain_id,omitempty"`
	ChainType        string `json:"chain_type,omitempty"`
	Delegated        bool   `json:"delegated,omitempty"`
	WalletClient     string `json:"wallet_client,omitempty"`
	WalletClientType string `json:"wallet_client_type,omitempty"`
	ConnectorType    string `json:"connector_type,omitempty"`
	Imported         bool   `json:"imported,omitempty"`
	RecoveryMethod   string `json:"recovery_method,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
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
}

// AdditionalSigner represents additional signers for wallet creation
type AdditionalSigner struct {
	SignerID          string   `json:"signer_id"`
	OverridePolicyIDs []string `json:"override_policy_ids,omitempty"`
}

func NewCreateEthWalletRequest(delegatedSignerId string) *CreateWalletRequest {
	return &CreateWalletRequest{
		PrivyWalletCreateRequestWallets: []*CreateWalletData{
			{
				ChainType: "ethereum",
				AdditionalSigners: []*AdditionalSigner{
					{
						SignerID: delegatedSignerId,
					},
				},
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
