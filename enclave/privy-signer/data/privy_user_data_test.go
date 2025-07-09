package data

import (
	"encoding/json"
	"testing"
	"time"
)

// Test data constants
const (
	testPrivyID        = "did:privy:clh8vxcmu0000jc08c7a8h5z9"
	testWalletID       = "wallet_123456"
	testEthAddress     = "0x1234567890123456789012345678901234567890"
	testSolAddress     = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
	testPublicKey      = "0x04ab123456789abcdef"
	testSignerID       = "signer_123456"
	testChainID        = "1"
	testEmailAddress   = "test@example.com"
	testWalletClient   = "metamask"
	testConnectorType  = "injected"
	testRecoveryMethod = "user-passcode"
)

// Helper function to create a test LinkedAccount
func createTestLinkedAccount(accountType, chainType string, delegated bool) LinkedAccount {
	account := LinkedAccount{
		Type:             accountType,
		VerifiedAt:       time.Now().Unix(),
		FirstVerifiedAt:  time.Now().Unix() - 3600,
		LatestVerifiedAt: time.Now().Unix(),
		Delegated:        delegated,
		ChainType:        chainType,
		WalletIndex:      0,
		ChainID:          testChainID,
		WalletClient:     testWalletClient,
		WalletClientType: "browser",
		ConnectorType:    testConnectorType,
		Imported:         false,
		RecoveryMethod:   testRecoveryMethod,
		PublicKey:        testPublicKey,
	}

	switch accountType {
	case "email":
		account.Address = testEmailAddress
	case "wallet":
		account.WalletID = testWalletID
		if chainType == "ethereum" {
			account.Address = testEthAddress
		} else if chainType == "solana" {
			account.Address = testSolAddress
		}
	}

	return account
}

// Helper function to create a test PrivyUser
func createTestPrivyUser() *PrivyUser {
	return &PrivyUser{
		PrivyID:   testPrivyID,
		CreatedAt: time.Now().Unix(),
		LinkedAccounts: []LinkedAccount{
			createTestLinkedAccount("email", "", false),
			createTestLinkedAccount("wallet", "ethereum", true),
			createTestLinkedAccount("wallet", "solana", true),
			createTestLinkedAccount("wallet", "ethereum", false),
		},
		MFAMethods:       []interface{}{},
		HasAcceptedTerms: true,
		IsGuest:          false,
	}
}

// Tests for PrivyUser methods
func TestPrivyUser_GetUsersEthDelegatedWallet(t *testing.T) {
	user := createTestPrivyUser()

	wallet := user.GetUsersEthDelegatedWallet()

	if wallet == nil {
		t.Fatal("Expected to find an Ethereum delegated wallet, but got nil")
	}

	if wallet.ChainType != "ethereum" {
		t.Errorf("Expected chain type to be 'ethereum', got %s", wallet.ChainType)
	}

	if !wallet.Delegated {
		t.Error("Expected wallet to be delegated")
	}

	if wallet.Address != testEthAddress {
		t.Errorf("Expected address to be %s, got %s", testEthAddress, wallet.Address)
	}
}

func TestPrivyUser_GetUsersEthDelegatedWallet_NotFound(t *testing.T) {
	user := &PrivyUser{
		PrivyID:   testPrivyID,
		CreatedAt: time.Now().Unix(),
		LinkedAccounts: []LinkedAccount{
			createTestLinkedAccount("email", "", false),
			createTestLinkedAccount("wallet", "ethereum", false), // Not delegated
			createTestLinkedAccount("wallet", "solana", true),    // Wrong chain type
		},
		MFAMethods:       []interface{}{},
		HasAcceptedTerms: true,
		IsGuest:          false,
	}

	wallet := user.GetUsersEthDelegatedWallet()

	if wallet != nil {
		t.Error("Expected no Ethereum delegated wallet to be found, but got one")
	}
}

func TestPrivyUser_GetUsersSolDelegatedWallet(t *testing.T) {
	user := createTestPrivyUser()

	wallet := user.GetUsersSolDelegatedWallet()

	if wallet == nil {
		t.Fatal("Expected to find a Solana delegated wallet, but got nil")
	}

	if wallet.ChainType != "solana" {
		t.Errorf("Expected chain type to be 'solana', got %s", wallet.ChainType)
	}

	if !wallet.Delegated {
		t.Error("Expected wallet to be delegated")
	}

	if wallet.Address != testSolAddress {
		t.Errorf("Expected address to be %s, got %s", testSolAddress, wallet.Address)
	}
}

func TestPrivyUser_GetUsersSolDelegatedWallet_NotFound(t *testing.T) {
	user := &PrivyUser{
		PrivyID:   testPrivyID,
		CreatedAt: time.Now().Unix(),
		LinkedAccounts: []LinkedAccount{
			createTestLinkedAccount("email", "", false),
			createTestLinkedAccount("wallet", "solana", false),  // Not delegated
			createTestLinkedAccount("wallet", "ethereum", true), // Wrong chain type
		},
		MFAMethods:       []interface{}{},
		HasAcceptedTerms: true,
		IsGuest:          false,
	}

	wallet := user.GetUsersSolDelegatedWallet()

	if wallet != nil {
		t.Error("Expected no Solana delegated wallet to be found, but got one")
	}
}

func TestPrivyUser_GetDelegatedWallets_EmptyLinkedAccounts(t *testing.T) {
	user := &PrivyUser{
		PrivyID:          testPrivyID,
		CreatedAt:        time.Now().Unix(),
		LinkedAccounts:   []LinkedAccount{},
		MFAMethods:       []interface{}{},
		HasAcceptedTerms: true,
		IsGuest:          false,
	}

	ethWallet := user.GetUsersEthDelegatedWallet()
	solWallet := user.GetUsersSolDelegatedWallet()

	if ethWallet != nil {
		t.Error("Expected no Ethereum delegated wallet in empty linked accounts")
	}

	if solWallet != nil {
		t.Error("Expected no Solana delegated wallet in empty linked accounts")
	}
}

// Tests for UnixTime
func TestUnixTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedVal func(*UnixTime) bool
	}{
		{
			name:        "Unix timestamp as number",
			input:       "1640995200", // January 1, 2022 00:00:00 UTC
			expectError: false,
			expectedVal: func(ut *UnixTime) bool {
				return ut.Time.Unix() == 1640995200
			},
		},
		{
			name:        "RFC3339 string",
			input:       `"2022-01-01T00:00:00Z"`,
			expectError: false,
			expectedVal: func(ut *UnixTime) bool {
				return ut.Time.Year() == 2022 && ut.Time.Month() == 1 && ut.Time.Day() == 1
			},
		},
		{
			name:        "Null value",
			input:       "null",
			expectError: false,
			expectedVal: func(ut *UnixTime) bool {
				return ut.Time.IsZero()
			},
		},
		{
			name:        "Invalid number",
			input:       "invalid",
			expectError: true,
			expectedVal: nil,
		},
		{
			name:        "Invalid RFC3339 string",
			input:       `"invalid-date"`,
			expectError: true,
			expectedVal: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ut UnixTime
			err := ut.UnmarshalJSON([]byte(tt.input))

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
				if tt.expectedVal != nil && !tt.expectedVal(&ut) {
					t.Error("Expected value validation failed")
				}
			}
		})
	}
}

func TestUnixTime_UnmarshalJSON_Integration(t *testing.T) {
	// Test with actual JSON unmarshaling
	jsonData := `{
		"created_at": 1640995200,
		"updated_at": "2022-01-01T00:00:00Z",
		"deleted_at": null
	}`

	var data struct {
		CreatedAt UnixTime `json:"created_at"`
		UpdatedAt UnixTime `json:"updated_at"`
		DeletedAt UnixTime `json:"deleted_at"`
	}

	err := json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %s", err.Error())
	}

	if data.CreatedAt.Unix() != 1640995200 {
		t.Errorf("Expected created_at to be 1640995200, got %d", data.CreatedAt.Unix())
	}

	if data.UpdatedAt.Year() != 2022 {
		t.Errorf("Expected updated_at year to be 2022, got %d", data.UpdatedAt.Year())
	}

	if !data.DeletedAt.IsZero() {
		t.Error("Expected deleted_at to be zero time for null value")
	}
}

// Tests for CreateWalletRequest and related structures
func TestNewCreateEthWalletRequest(t *testing.T) {
	req := NewCreateEthWalletRequest(testSignerID)

	if req == nil {
		t.Fatal("Expected non-nil CreateWalletRequest")
	}

	if len(req.PrivyWalletCreateRequestWallets) != 1 {
		t.Errorf("Expected 1 wallet in request, got %d", len(req.PrivyWalletCreateRequestWallets))
	}

	wallet := req.PrivyWalletCreateRequestWallets[0]
	if wallet.ChainType != "ethereum" {
		t.Errorf("Expected chain type to be 'ethereum', got %s", wallet.ChainType)
	}

	if len(wallet.AdditionalSigners) != 1 {
		t.Errorf("Expected 1 additional signer, got %d", len(wallet.AdditionalSigners))
	}

	signer := wallet.AdditionalSigners[0]
	if signer.SignerID != testSignerID {
		t.Errorf("Expected signer ID to be %s, got %s", testSignerID, signer.SignerID)
	}
}

func TestCreateWalletData_Fields(t *testing.T) {
	data := &CreateWalletData{
		ChainType:         "ethereum",
		CreateSmartWallet: true,
		AdditionalSigners: []*AdditionalSigner{
			{
				SignerID:          testSignerID,
				OverridePolicyIDs: []string{"policy1", "policy2"},
			},
		},
	}

	if data.ChainType != "ethereum" {
		t.Errorf("Expected chain type to be 'ethereum', got %s", data.ChainType)
	}

	if !data.CreateSmartWallet {
		t.Error("Expected CreateSmartWallet to be true")
	}

	if len(data.AdditionalSigners) != 1 {
		t.Errorf("Expected 1 additional signer, got %d", len(data.AdditionalSigners))
	}

	signer := data.AdditionalSigners[0]
	if signer.SignerID != testSignerID {
		t.Errorf("Expected signer ID to be %s, got %s", testSignerID, signer.SignerID)
	}

	if len(signer.OverridePolicyIDs) != 2 {
		t.Errorf("Expected 2 override policy IDs, got %d", len(signer.OverridePolicyIDs))
	}
}

func TestAdditionalSigner_Fields(t *testing.T) {
	signer := &AdditionalSigner{
		SignerID:          testSignerID,
		OverridePolicyIDs: []string{"policy1", "policy2", "policy3"},
	}

	if signer.SignerID != testSignerID {
		t.Errorf("Expected signer ID to be %s, got %s", testSignerID, signer.SignerID)
	}

	if len(signer.OverridePolicyIDs) != 3 {
		t.Errorf("Expected 3 override policy IDs, got %d", len(signer.OverridePolicyIDs))
	}

	expectedPolicies := []string{"policy1", "policy2", "policy3"}
	for i, policy := range signer.OverridePolicyIDs {
		if policy != expectedPolicies[i] {
			t.Errorf("Expected policy %d to be %s, got %s", i, expectedPolicies[i], policy)
		}
	}
}

// Tests for CreateWalletResponse
func TestCreateWalletResponse_Fields(t *testing.T) {
	now := time.Now()
	response := &CreateWalletResponse{
		ID:        testWalletID,
		CreatedAt: UnixTime{Time: now},
		LinkedAccounts: []*LinkedAccount{
			{
				WalletID:   testWalletID,
				Type:       "wallet",
				ChainType:  "ethereum",
				Address:    testEthAddress,
				Delegated:  true,
				VerifiedAt: now.Unix(),
			},
		},
		CustomMetadata: map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		},
	}

	if response.ID != testWalletID {
		t.Errorf("Expected ID to be %s, got %s", testWalletID, response.ID)
	}

	if !response.CreatedAt.Time.Equal(now) {
		t.Errorf("Expected created_at to be %v, got %v", now, response.CreatedAt.Time)
	}

	if len(response.LinkedAccounts) != 1 {
		t.Errorf("Expected 1 linked account, got %d", len(response.LinkedAccounts))
	}

	account := response.LinkedAccounts[0]
	if account.WalletID != testWalletID {
		t.Errorf("Expected wallet ID to be %s, got %s", testWalletID, account.WalletID)
	}

	if account.ChainType != "ethereum" {
		t.Errorf("Expected chain type to be 'ethereum', got %s", account.ChainType)
	}

	if !account.Delegated {
		t.Error("Expected wallet to be delegated")
	}

	if response.CustomMetadata == nil {
		t.Error("Expected custom metadata to be present")
	}
}

// Tests for LinkedAccount
func TestLinkedAccount_EmailAccount(t *testing.T) {
	account := createTestLinkedAccount("email", "", false)

	if account.Type != "email" {
		t.Errorf("Expected type to be 'email', got %s", account.Type)
	}

	if account.Address != testEmailAddress {
		t.Errorf("Expected address to be %s, got %s", testEmailAddress, account.Address)
	}

	if account.Delegated {
		t.Error("Expected email account to not be delegated")
	}

	if account.ChainType != "" {
		t.Errorf("Expected chain type to be empty for email account, got %s", account.ChainType)
	}
}

func TestLinkedAccount_WalletAccount(t *testing.T) {
	account := createTestLinkedAccount("wallet", "ethereum", true)

	if account.Type != "wallet" {
		t.Errorf("Expected type to be 'wallet', got %s", account.Type)
	}

	if account.ChainType != "ethereum" {
		t.Errorf("Expected chain type to be 'ethereum', got %s", account.ChainType)
	}

	if !account.Delegated {
		t.Error("Expected wallet to be delegated")
	}

	if account.Address != testEthAddress {
		t.Errorf("Expected address to be %s, got %s", testEthAddress, account.Address)
	}

	if account.WalletID != testWalletID {
		t.Errorf("Expected wallet ID to be %s, got %s", testWalletID, account.WalletID)
	}

	if account.PublicKey != testPublicKey {
		t.Errorf("Expected public key to be %s, got %s", testPublicKey, account.PublicKey)
	}
}

// JSON marshaling/unmarshaling tests
func TestLinkedAccount_JSONSerialization(t *testing.T) {
	original := createTestLinkedAccount("wallet", "ethereum", true)

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal LinkedAccount: %s", err.Error())
	}

	// Unmarshal back
	var unmarshaled LinkedAccount
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal LinkedAccount: %s", err.Error())
	}

	// Compare key fields
	if unmarshaled.Type != original.Type {
		t.Errorf("Type mismatch: expected %s, got %s", original.Type, unmarshaled.Type)
	}

	if unmarshaled.ChainType != original.ChainType {
		t.Errorf("ChainType mismatch: expected %s, got %s", original.ChainType, unmarshaled.ChainType)
	}

	if unmarshaled.Delegated != original.Delegated {
		t.Errorf("Delegated mismatch: expected %t, got %t", original.Delegated, unmarshaled.Delegated)
	}

	if unmarshaled.Address != original.Address {
		t.Errorf("Address mismatch: expected %s, got %s", original.Address, unmarshaled.Address)
	}
}

func TestPrivyUser_JSONSerialization(t *testing.T) {
	original := createTestPrivyUser()

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal PrivyUser: %s", err.Error())
	}

	// Unmarshal back
	var unmarshaled PrivyUser
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal PrivyUser: %s", err.Error())
	}

	// Compare key fields
	if unmarshaled.PrivyID != original.PrivyID {
		t.Errorf("PrivyID mismatch: expected %s, got %s", original.PrivyID, unmarshaled.PrivyID)
	}

	if len(unmarshaled.LinkedAccounts) != len(original.LinkedAccounts) {
		t.Errorf("LinkedAccounts length mismatch: expected %d, got %d", len(original.LinkedAccounts), len(unmarshaled.LinkedAccounts))
	}

	if unmarshaled.HasAcceptedTerms != original.HasAcceptedTerms {
		t.Errorf("HasAcceptedTerms mismatch: expected %t, got %t", original.HasAcceptedTerms, unmarshaled.HasAcceptedTerms)
	}

	if unmarshaled.IsGuest != original.IsGuest {
		t.Errorf("IsGuest mismatch: expected %t, got %t", original.IsGuest, unmarshaled.IsGuest)
	}
}

// Edge case and error handling tests
func TestPrivyUser_EdgeCases(t *testing.T) {
	t.Run("Multiple delegated wallets of same type", func(t *testing.T) {
		user := &PrivyUser{
			PrivyID:   testPrivyID,
			CreatedAt: time.Now().Unix(),
			LinkedAccounts: []LinkedAccount{
				createTestLinkedAccount("wallet", "ethereum", true),
				createTestLinkedAccount("wallet", "ethereum", true), // Another one
			},
		}

		// Should return the first one found
		wallet := user.GetUsersEthDelegatedWallet()
		if wallet == nil {
			t.Error("Expected to find an Ethereum delegated wallet")
		}
	})

	t.Run("Mixed wallet types", func(t *testing.T) {
		user := &PrivyUser{
			PrivyID:   testPrivyID,
			CreatedAt: time.Now().Unix(),
			LinkedAccounts: []LinkedAccount{
				createTestLinkedAccount("wallet", "ethereum", false),
				createTestLinkedAccount("wallet", "polygon", true),
				createTestLinkedAccount("wallet", "solana", true),
			},
		}

		ethWallet := user.GetUsersEthDelegatedWallet()
		solWallet := user.GetUsersSolDelegatedWallet()

		if ethWallet != nil {
			t.Error("Should not find Ethereum delegated wallet")
		}

		if solWallet == nil {
			t.Error("Should find Solana delegated wallet")
		}
	})
}

func TestCreateWalletRequest_EdgeCases(t *testing.T) {
	t.Run("Empty signer ID", func(t *testing.T) {
		req := NewCreateEthWalletRequest("")

		if req == nil {
			t.Fatal("Expected non-nil request even with empty signer ID")
		}

		if len(req.PrivyWalletCreateRequestWallets) != 1 {
			t.Error("Expected 1 wallet in request")
		}

		signer := req.PrivyWalletCreateRequestWallets[0].AdditionalSigners[0]
		if signer.SignerID != "" {
			t.Error("Expected empty signer ID to be preserved")
		}
	})

	t.Run("Multiple additional signers", func(t *testing.T) {
		data := &CreateWalletData{
			ChainType: "ethereum",
			AdditionalSigners: []*AdditionalSigner{
				{SignerID: "signer1"},
				{SignerID: "signer2"},
				{SignerID: "signer3"},
			},
		}

		if len(data.AdditionalSigners) != 3 {
			t.Errorf("Expected 3 additional signers, got %d", len(data.AdditionalSigners))
		}

		for i, signer := range data.AdditionalSigners {
			expectedID := "signer" + string(rune('1'+i))
			if signer.SignerID != expectedID {
				t.Errorf("Expected signer %d to have ID %s, got %s", i, expectedID, signer.SignerID)
			}
		}
	})
}
