package privysigner

import (
	"sync/atomic"
	"testing"

	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

func ethWalletCount(user data.PrivyUser) int {
	n := 0
	for _, acc := range user.LinkedAccounts {
		if acc.Delegated && acc.ChainType == "ethereum" {
			n++
		}
	}
	return n
}

// The cache must already agree with Privy by the time the create call returns, so a caller
// that provisions a wallet and immediately signs with it finds the wallet there.
func TestCreateUserWallet_CacheIsConsistentBeforeReturning(t *testing.T) {
	cli, _ := newWalletProvisioningClient(t, 0)

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}

	item := cli.userCache.Get(walletTestPrivyID)
	if item == nil {
		t.Fatal("user record is not cached after creating a wallet")
	}
	cached := item.Value()

	if cached.GetEthDelegatedWalletByAddress(wallet.Address) == nil {
		t.Error("the newly created wallet is missing from the cached user record")
	}
	if cached.GetEthDelegatedWalletByAddress(walletZeroAddr) == nil {
		t.Error("wallet 0 was lost from the cached user record")
	}
	if got := ethWalletCount(cached); got != 2 {
		t.Errorf("cached delegated eth wallets = %d, want 2", got)
	}
}

// Following the create with a signature must not need another round trip: the record was
// written back rather than evicted, so there is nothing to refetch.
func TestCreateUserWallet_NewWalletResolvesWithoutARefetch(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}
	fetches := atomic.LoadInt64(&state.getCount)

	resolved, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, wallet.Address)
	if httpErr != nil {
		t.Fatalf("newly created wallet did not resolve: %+v", httpErr)
	}
	if resolved.WalletID != wallet.WalletID {
		t.Errorf("resolved wallet %s, want %s", resolved.WalletID, wallet.WalletID)
	}
	if got := atomic.LoadInt64(&state.getCount); got != fetches {
		t.Errorf("Privy GETs = %d, want %d (the create should have left the cache usable)", got, fetches)
	}
}

// Merging the create response must not reach through the shallow copy GetUser hands out
// and mutate the cached record in place.
func TestCreateUserWallet_DoesNotMutateTheCachedRecordInPlace(t *testing.T) {
	cli, _ := newWalletProvisioningClient(t, 0)

	user, httpErr := cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}
	// A handle taken before the create, as a concurrent signature would hold.
	before := *user

	if _, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose); httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}

	if got := ethWalletCount(before); got != 1 {
		t.Errorf("a user record read before the create now reports %d wallets, want 1 — the merge wrote through a shared backing array", got)
	}
}

// The TTL has to be a ceiling measured from the last real read. Left to slide, the users
// who sign most would be the ones whose record is never refreshed.
func TestUserCache_TTLDoesNotSlideOnReads(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)

	if _, httpErr := cli.GetUser(walletTestPrivyID); httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}
	before := cli.userCache.Get(walletTestPrivyID).ExpiresAt()

	for i := 0; i < 5; i++ {
		if _, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletZeroAddr); httpErr != nil {
			t.Fatalf("resolveDelegatedWallet() error = %+v", httpErr)
		}
	}

	if after := cli.userCache.Get(walletTestPrivyID).ExpiresAt(); !after.Equal(before) {
		t.Errorf("user TTL slid forward on reads: %v -> %v", before, after)
	}
	if got := atomic.LoadInt64(&state.getCount); got != 1 {
		t.Errorf("Privy GETs = %d, want 1", got)
	}
}
