package data

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
