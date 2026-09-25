package data

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	walletZero = "0xaaaa000000000000000000000000000000000001"
	walletOne  = "0xbbbb000000000000000000000000000000000002"
)

// twoWalletUser is a user holding two delegated eth wallets plus noise: a solana wallet,
// an undelegated eth wallet, and an email account.
func twoWalletUser() *PrivyUser {
	return &PrivyUser{
		PrivyID: "did:privy:twowallets",
		LinkedAccounts: []LinkedAccount{
			{Type: "email", Address: "user@example.com"},
			{WalletID: "w0", Type: "wallet", Address: walletZero, ChainType: "ethereum", Delegated: true, WalletIndex: 0},
			{WalletID: "w1", Type: "wallet", Address: walletOne, ChainType: "ethereum", Delegated: true, WalletIndex: 1},
			{WalletID: "wsol", Type: "wallet", Address: "So11111111111111111111111111111111111111112", ChainType: "solana", Delegated: true},
			{WalletID: "wund", Type: "wallet", Address: "0xcccc000000000000000000000000000000000003", ChainType: "ethereum", Delegated: false},
		},
	}
}

func TestGetEthDelegatedWalletByAddress_SelectsTheNamedWallet(t *testing.T) {
	user := twoWalletUser()

	for _, tc := range []struct {
		name    string
		address string
		wantID  string
		wantIdx int
	}{
		{name: "wallet zero", address: walletZero, wantID: "w0", wantIdx: 0},
		{name: "wallet one", address: walletOne, wantID: "w1", wantIdx: 1},
		{name: "checksummed casing", address: "0x" + strings.ToUpper(walletOne[2:]), wantID: "w1", wantIdx: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := user.GetEthDelegatedWalletByAddress(tc.address)
			if got == nil {
				t.Fatalf("GetEthDelegatedWalletByAddress(%s) = nil, want wallet %s", tc.address, tc.wantID)
			}
			if got.WalletID != tc.wantID {
				t.Errorf("WalletID = %v, want %v", got.WalletID, tc.wantID)
			}
			if got.WalletIndex != tc.wantIdx {
				t.Errorf("WalletIndex = %v, want %v", got.WalletIndex, tc.wantIdx)
			}
		})
	}
}

// The enclave must never substitute another wallet for one it cannot find. Every case
// here has to come back nil so the caller returns an error rather than a signature from
// the wrong key.
func TestGetEthDelegatedWalletByAddress_RejectsAnythingElse(t *testing.T) {
	user := twoWalletUser()

	for _, tc := range []struct {
		name    string
		address string
	}{
		{name: "unknown address", address: "0xdead000000000000000000000000000000000009"},
		{name: "empty address", address: ""},
		{name: "another chain", address: "So11111111111111111111111111111111111111112"},
		{name: "undelegated eth wallet", address: "0xcccc000000000000000000000000000000000003"},
		// LinkedAccount.Address carries email addresses too, so the delegated/chain_type
		// filter is what stops a non-wallet account from satisfying the lookup.
		{name: "email account", address: "user@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := user.GetEthDelegatedWalletByAddress(tc.address); got != nil {
				t.Errorf("GetEthDelegatedWalletByAddress(%q) = %+v, want nil", tc.address, got)
			}
		})
	}
}

func TestAxalAuthPayloadBindsTheWallet(t *testing.T) {
	req := NewAxalEthSecp256k1SignRequest("0xhash", "did:privy:abc", walletOne)

	want := "0xhash:did:privy:abc:" + walletOne
	if got := req.AuthPayload(); got != want {
		t.Errorf("AuthPayload() = %q, want %q", got, want)
	}

	// Stripping the wallet from the body leaves an HMAC computed over the 3-part string,
	// which cannot validate against the 2-part one. That is what keeps the wallet field
	// authenticated rather than merely asserted.
	if req.AuthPayload() == req.Params.Hash+":"+req.PrivyID {
		t.Error("3-part preimage collides with the legacy 2-part preimage")
	}

	// Redirecting the signature to the user's other wallet changes the preimage, so the
	// original HMAC no longer verifies.
	other := NewAxalEthSecp256k1SignRequest("0xhash", "did:privy:abc", walletZero)
	if other.AuthPayload() == req.AuthPayload() {
		t.Error("preimage does not distinguish between the user's two wallets")
	}
}

func TestAxalAuthPayloadIsCaseStable(t *testing.T) {
	lower := NewAxalEthSecp256k1SignRequest("0xhash", "did:privy:abc", walletOne)
	upper := NewAxalEthSecp256k1SignRequest("0xhash", "did:privy:abc", "0x"+strings.ToUpper(walletOne[2:]))

	if lower.AuthPayload() != upper.AuthPayload() {
		t.Errorf("preimage depends on address casing:\n lower = %q\n upper = %q",
			lower.AuthPayload(), upper.AuthPayload())
	}
}

// wallet_index 0 is a real wallet, not an absent value. It used to be dropped by
// omitempty, which made wallet 0 read as undefined to whoever consumed GET /user.
func TestWalletIndexZeroIsSerialized(t *testing.T) {
	b, err := json.Marshal(LinkedAccount{
		WalletID: "w0", Type: "wallet", Address: walletZero,
		ChainType: "ethereum", Delegated: true, WalletIndex: 0,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if _, ok := decoded["wallet_index"]; !ok {
		t.Errorf("wallet_index missing for wallet 0: %s", b)
	}
	if _, ok := decoded["delegated"]; !ok {
		t.Errorf("delegated missing: %s", b)
	}
}

// ExternalIDBelongsToUser is an ownership check, so its failures matter more than its
// successes: a quorum-owned wallet is absent from the user's linked accounts, and this is what
// stands in for the record that would otherwise prove the wallet is theirs.
func TestExternalIDBelongsToUser(t *testing.T) {
	const privyId = "did:privy:cm00000000000000000001"

	tests := map[string]struct {
		externalID string
		want       bool
	}{
		"the id this enclave assigns":          {"cm00000000000000000001-wealth_plan", true},
		"another purpose for this user":        {"cm00000000000000000001-savings", true},
		"another user's subject":               {"cm00000000000000000002-wealth_plan", false},
		"this subject inside a longer one":     {"xcm00000000000000000001-wealth_plan", false},
		"the subject with no purpose":          {"cm00000000000000000001-", false},
		"the subject alone":                    {"cm00000000000000000001", false},
		"a purpose that is not one we mint":    {"cm00000000000000000001-Wealth_Plan", false},
		"a purpose with a dot":                 {"cm00000000000000000001-wealth.plan", false},
		"empty":                                {"", false},
		"the full did rather than the subject": {"did:privy:cm00000000000000000001-wealth_plan", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ExternalIDBelongsToUser(tc.externalID, privyId); got != tc.want {
				t.Errorf("ExternalIDBelongsToUser(%q, %q) = %t, want %t", tc.externalID, privyId, got, tc.want)
			}
		})
	}
}

// Every id the enclave mints must satisfy the check that later reads it back, or a wallet it
// provisioned would become unusable the moment signing tried to verify ownership.
func TestExternalIDBelongsToUser_AcceptsEveryIDWeMint(t *testing.T) {
	for _, privyId := range []string{
		"did:privy:cm00000000000000000001",
		"did:privy:cmdj1wama016kl10j78iaj1bq",
	} {
		for _, purpose := range []string{"wealth_plan", "savings", "a", "long-purpose-name_2"} {
			externalID, err := WalletExternalID(privyId, purpose)
			if err != nil {
				t.Fatalf("WalletExternalID(%q, %q) error = %v", privyId, purpose, err)
			}

			if !ExternalIDBelongsToUser(externalID, privyId) {
				t.Errorf("ExternalIDBelongsToUser(%q, %q) = false, want true", externalID, privyId)
			}
		}
	}
}
