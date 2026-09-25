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

// Creates the request that provisions a user's embedded eth wallet, the one at HD index 0.
//
// It carries no external id, because this endpoint does not mint wallets on demand: it
// provisions the embedded wallet a user does not yet have and answers 200 without creating
// anything for a chain type they already hold. An external id here would be assigned to a
// wallet only on the very first provision and silently dropped afterwards. Purpose-built
// wallets are created with NewCreateDelegatedEthWalletRequest instead.
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

// CreateWalletForOwnerRequest creates a wallet on Privy's wallet API, owned by a user.
//
// This is not the same call as CreateWalletRequest, which posts to a user's own wallets
// collection and only provisions the embedded wallet a user does not yet have — it is a
// no-op for a chain type the user already holds, which is no way to add a second wallet.
// This one mints a wallet per call, which is what a purpose-built wallet needs.
//
// Owner and additional signer are different roles and both are load bearing. The user owns
// the wallet, so it is theirs and appears on their account; our key quorum is attached as an
// additional signer, which is what authorises Axal-initiated signing. Setting our quorum as
// the owner instead would take the wallet away from the user.
type CreateWalletForOwnerRequest struct {
	ChainType         string              `json:"chain_type"`
	ExternalID        string              `json:"external_id,omitempty"`
	Owner             *WalletOwner        `json:"owner,omitempty"`
	AdditionalSigners []*AdditionalSigner `json:"additional_signers,omitempty"`
}

// WalletOwner names the Privy user a wallet belongs to.
type WalletOwner struct {
	UserID string `json:"user_id"`
}

func NewCreateDelegatedEthWalletRequest(privyId string, delegatedSignerId string, externalID string) *CreateWalletForOwnerRequest {
	return &CreateWalletForOwnerRequest{
		ChainType:  "ethereum",
		ExternalID: externalID,
		Owner:      &WalletOwner{UserID: privyId},
		AdditionalSigners: []*AdditionalSigner{
			{SignerID: delegatedSignerId},
		},
	}
}

// WalletByAddressRequest looks a wallet up by its address.
type WalletByAddressRequest struct {
	Address string `json:"address"`
}

// PrivyWallet is the wallet object Privy's wallet endpoints return.
//
// It is not a linked_accounts entry and the two are not interchangeable. This carries the
// wallet's signer configuration, which the user object does not expose, and lacks
// wallet_index and delegated, which only the user object has.
type PrivyWallet struct {
	ID                string              `json:"id"`
	Address           string              `json:"address"`
	ChainType         string              `json:"chain_type,omitempty"`
	ExternalID        string              `json:"external_id,omitempty"`
	PublicKey         string              `json:"public_key,omitempty"`
	OwnerID           string              `json:"owner_id,omitempty"`
	AdditionalSigners []*AdditionalSigner `json:"additional_signers,omitempty"`
}

// Reports whether a key quorum is attached to the wallet as an additional signer.
//
// This is what authorises Axal-initiated signing: the /rpc call is accepted because the
// request is signed by this quorum's key. It is the difference between a wallet the enclave
// can rebalance from and one only its user can ever move, so it is checked rather than
// assumed for a wallet we did not watch being created.
func (w *PrivyWallet) HasAdditionalSigner(signerID string) bool {
	if signerID == "" {
		return false
	}

	for _, signer := range w.AdditionalSigners {
		if signer != nil && signer.SignerID == signerID {
			return true
		}
	}

	return false
}

// The identifier Privy's wallet endpoints accept in place of a wallet id, for a wallet
// carrying an external id.
func ExternalWalletRef(externalID string) string {
	return "ext_wal_" + externalID
}

// CreateWalletResponse represents the response for creating a single wallet
type CreateWalletResponse struct {
	ID             string           `json:"id"`
	CreatedAt      UnixTime         `json:"created_at"`
	LinkedAccounts []*LinkedAccount `json:"linked_accounts"`
	CustomMetadata interface{}      `json:"custom_metadata,omitempty"`
}
