package privysigner

import (
	"testing"

	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

// Privy may echo the user's whole account set on a create-wallet response rather than
// only the wallet just created. The merge has to keep every wallet a user holds -- they
// are selected by address at signing time, so a dropped wallet is an unsignable one --
// while not duplicating wallets already on the user.
func TestMergeLinkedAccounts(t *testing.T) {
	existing := data.LinkedAccount{
		WalletID: "w0", Type: "wallet", Address: "0xaaa1",
		ChainType: "ethereum", Delegated: true, WalletIndex: 0,
	}

	t.Run("keeps both wallets when a second is created", func(t *testing.T) {
		user := &data.PrivyUser{LinkedAccounts: []data.LinkedAccount{existing}}

		mergeLinkedAccounts(user, []*data.LinkedAccount{{
			WalletID: "w1", Type: "wallet", Address: "0xbbb2",
			ChainType: "ethereum", Delegated: true, WalletIndex: 1,
		}})

		if len(user.LinkedAccounts) != 2 {
			t.Fatalf("len(LinkedAccounts) = %d, want 2: %+v", len(user.LinkedAccounts), user.LinkedAccounts)
		}
		if user.GetEthDelegatedWalletByAddress("0xaaa1") == nil {
			t.Error("wallet 0 was dropped by the merge")
		}
		if user.GetEthDelegatedWalletByAddress("0xbbb2") == nil {
			t.Error("wallet 1 was not added by the merge")
		}
	})

	t.Run("does not duplicate a wallet the response echoes back", func(t *testing.T) {
		user := &data.PrivyUser{LinkedAccounts: []data.LinkedAccount{existing}}

		// The full account set, as Privy would return it after creating w1.
		mergeLinkedAccounts(user, []*data.LinkedAccount{
			{WalletID: "w0", Type: "wallet", Address: "0xaaa1", ChainType: "ethereum", Delegated: true, WalletIndex: 0},
			{WalletID: "w1", Type: "wallet", Address: "0xbbb2", ChainType: "ethereum", Delegated: true, WalletIndex: 1},
		})

		if len(user.LinkedAccounts) != 2 {
			t.Fatalf("len(LinkedAccounts) = %d, want 2: %+v", len(user.LinkedAccounts), user.LinkedAccounts)
		}
	})

	t.Run("keeps every eth wallet, not just the first delegated one", func(t *testing.T) {
		user := &data.PrivyUser{}

		mergeLinkedAccounts(user, []*data.LinkedAccount{
			{WalletID: "w0", Type: "wallet", Address: "0xaaa1", ChainType: "ethereum", Delegated: true},
			{WalletID: "w1", Type: "wallet", Address: "0xbbb2", ChainType: "ethereum", Delegated: true},
			{WalletID: "w2", Type: "wallet", Address: "0xccc3", ChainType: "ethereum", Delegated: true},
		})

		if len(user.LinkedAccounts) != 3 {
			t.Fatalf("len(LinkedAccounts) = %d, want 3: %+v", len(user.LinkedAccounts), user.LinkedAccounts)
		}
		for _, addr := range []string{"0xaaa1", "0xbbb2", "0xccc3"} {
			if user.GetEthDelegatedWalletByAddress(addr) == nil {
				t.Errorf("wallet %s was dropped by the merge", addr)
			}
		}
	})

	t.Run("tolerates nil entries", func(t *testing.T) {
		user := &data.PrivyUser{LinkedAccounts: []data.LinkedAccount{existing}}
		mergeLinkedAccounts(user, []*data.LinkedAccount{nil})

		if len(user.LinkedAccounts) != 1 {
			t.Fatalf("len(LinkedAccounts) = %d, want 1", len(user.LinkedAccounts))
		}
	})
}
