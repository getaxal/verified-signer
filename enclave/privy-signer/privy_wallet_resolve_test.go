package privysigner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/jellydator/ttlcache/v3"
)

// The external id a wealth_plan wallet for the test user carries.
const resolveExternalID = "cm00000000000000000001-" + wealthPurpose

// resolveServer mocks the two reads resolveCreatedWallet depends on: the user record, and
// the wallet-by-external-id lookup.
//
// It is deliberately not walletProvisioningServer. That one derives its answers from a
// create it performed, and every case worth testing here is one where the create has
// already happened and only identification is left — so what each read returns has to be
// dictated per test rather than earned.
type resolveServer struct {
	mu sync.Mutex

	// The user record Privy serves. Swapped mid-test to stand for a create that landed
	// between two reads.
	accounts []data.LinkedAccount

	// The wallet the external-id lookup resolves, or nil for Privy's 404.
	wallet *data.PrivyWallet

	// Non-zero to fail that read with this status instead of answering it.
	userStatus   int
	lookupStatus int

	getCount    int64
	lookupCount int64
	postCount   int64
}

func (s *resolveServer) setAccounts(accounts []data.LinkedAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accounts = accounts
}

func (s *resolveServer) setWallet(wallet *data.PrivyWallet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.wallet = wallet
}

func (s *resolveServer) snapshot() ([]data.LinkedAccount, *data.PrivyWallet, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.accounts, s.wallet, s.userStatus, s.lookupStatus
}

// A delegated eth wallet at HD index 0, which every test user holds: without one, GetUser
// provisions it and the mock would be answering a create it is not the subject of.
func walletZeroAccount() data.LinkedAccount {
	return data.LinkedAccount{
		WalletID: "w0", Type: "wallet", Address: walletZeroAddr,
		ChainType: "ethereum", Delegated: true, WalletIndex: 0,
	}
}

// The wallet a create has just minted, as the user record carries it.
func walletOneAccount(externalID string) data.LinkedAccount {
	return data.LinkedAccount{
		WalletID: "w1", Type: "wallet", Address: walletOneAddr,
		ChainType: "ethereum", Delegated: true, WalletIndex: 1,
		ExternalID: externalID,
	}
}

// The same wallet as the wallet endpoint returns it: signers attached, no index and no
// delegated flag, because the wallet object carries neither.
func walletOneObject() *data.PrivyWallet {
	return &data.PrivyWallet{
		ID:         "w1",
		Address:    walletOneAddr,
		ChainType:  "ethereum",
		ExternalID: resolveExternalID,
		AdditionalSigners: []*data.AdditionalSigner{
			{SignerID: "test-signer-id"},
		},
	}
}

func newResolveClient(t *testing.T, state *resolveServer) *PrivyClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accounts, wallet, userStatus, lookupStatus := state.snapshot()

		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/users/"):
			atomic.AddInt64(&state.getCount, 1)

			if userStatus != 0 {
				w.WriteHeader(userStatus)
				_, _ = w.Write([]byte(`{"error":"user read failed"}`))
				return
			}

			b, _ := json.Marshal(data.PrivyUser{
				PrivyID:        walletTestPrivyID,
				LinkedAccounts: accounts,
			})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodPost && r.URL.Path == "/v1/wallets/address":
			atomic.AddInt64(&state.lookupCount, 1)

			if lookupStatus != 0 {
				w.WriteHeader(lookupStatus)
				_, _ = w.Write([]byte(`{"error":"wallet lookup failed"}`))
				return
			}

			var body data.WalletByAddressRequest
			_ = json.NewDecoder(r.Body).Decode(&body)

			if wallet == nil || !strings.EqualFold(body.Address, wallet.Address) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"wallet not found"}`))
				return
			}

			b, _ := json.Marshal(wallet)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/wallets/"):
			atomic.AddInt64(&state.lookupCount, 1)

			if lookupStatus != 0 {
				w.WriteHeader(lookupStatus)
				_, _ = w.Write([]byte(`{"error":"wallet lookup failed"}`))
				return
			}

			ref := strings.TrimPrefix(r.URL.Path, "/v1/wallets/")
			if wallet == nil || ref != data.ExternalWalletRef(wallet.ExternalID) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"wallet not found"}`))
				return
			}

			b, _ := json.Marshal(wallet)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		// Identification must never create anything. A create reaching this handler means
		// the wallet the test set up was not found, so the test is no longer measuring what
		// it claims to.
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wallets"):
			atomic.AddInt64(&state.postCount, 1)
			t.Errorf("unexpected create-wallet POST while identifying an existing wallet")
			w.WriteHeader(http.StatusInternalServerError)

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	cache := ttlcache.New(
		ttlcache.WithTTL[string, data.PrivyUser](userCacheTTL),
		ttlcache.WithCapacity[string, data.PrivyUser](cacheCapacity),
		ttlcache.WithDisableTouchOnHit[string, data.PrivyUser](),
	)

	return &PrivyClient{
		Environment: "test",
		baseUrl:     server.URL,
		client:      server.Client(),
		teeConfig: &enclave.TEEConfig{
			Privy: enclave.PrivyConfig{
				AppID:                 "test-app",
				DelegatedActionsKeyId: "test-signer-id",
			},
		},
		userCache: cache,
	}
}

// The lookup by external id resolves the wallet without the user record being involved at all.
// A purpose wallet is owned by a key quorum and never appears among the user's linked accounts,
// so the wallet object has to be able to carry the whole answer.
func TestFindWalletByExternalID_ResolvesFromTheWalletAlone(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v", httpErr)
	}
	if wallet == nil {
		t.Fatal("findWalletByExternalID() = nil, want the wallet Privy holds under the external id")
	}

	if wallet.WalletID != "w1" {
		t.Errorf("WalletID = %q, want w1 — the id is what signing addresses", wallet.WalletID)
	}
	if wallet.Address != walletOneAddr {
		t.Errorf("Address = %s, want %s", wallet.Address, walletOneAddr)
	}
	if wallet.ExternalID != resolveExternalID {
		t.Errorf("ExternalID = %q, want %q", wallet.ExternalID, resolveExternalID)
	}

	// Set from the attached quorum rather than copied from Privy, which reports no delegated
	// flag for a quorum-owned wallet. Everything downstream reads this as "Axal can sign".
	if !wallet.Delegated {
		t.Error("resolved wallet is not marked delegated, so the signing path would refuse it")
	}

	if got := atomic.LoadInt64(&state.getCount); got != 0 {
		t.Errorf("user fetches = %d, want 0: the wallet object is the whole source of truth", got)
	}
}

// No wallet under the external id is an answer, not a failure: it is what tells the caller
// this purpose has never been provisioned and a create is due.
func TestFindWalletByExternalID_ReturnsNilWhenNoWalletExists(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v, want a nil wallet and no error", httpErr)
	}
	if wallet != nil {
		t.Errorf("findWalletByExternalID() = %+v, want nil", wallet)
	}
}

// A lookup that fails is not a lookup that found nothing. Treating the two alike would read
// a Privy outage as "no wallet exists" and let the caller create a second one.
func TestFindWalletByExternalID_PropagatesALookupFailure(t *testing.T) {
	state := &resolveServer{
		accounts:     []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		lookupStatus: http.StatusInternalServerError,
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr == nil {
		t.Fatalf("findWalletByExternalID() returned wallet %+v, want the lookup failure", wallet)
	}
	if got := atomic.LoadInt64(&state.getCount); got != 0 {
		t.Errorf("user fetches = %d, want 0: a failed lookup must not be answered by guessing from the user record", got)
	}
}

// Axal's key quorum has to be attached, or the wallet serves user-initiated signing and fails
// every Axal-initiated one — rebalancing and reward claiming — silently. A wallet without it
// is rejected before the user record is even consulted.
func TestAccountForWallet_RejectsAWalletWithoutAxalsSigner(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount(resolveExternalID)},
	}
	cli := newResolveClient(t, state)

	for name, signers := range map[string][]*data.AdditionalSigner{
		"no signers":      nil,
		"another quorum":  {{SignerID: "someone-elses-quorum"}},
		"an empty signer": {{SignerID: ""}},
	} {
		t.Run(name, func(t *testing.T) {
			wallet := walletOneObject()
			wallet.AdditionalSigners = signers

			account, httpErr := cli.accountForWallet(walletTestPrivyID, resolveExternalID, wallet)
			if httpErr == nil {
				t.Fatalf("accountForWallet() returned %+v, want a wallet Axal cannot sign for to be rejected", account)
			}
			if httpErr.Code != http.StatusInternalServerError {
				t.Errorf("Code = %d, want 500", httpErr.Code)
			}
		})
	}
}

// The signer check is not enough on its own: a quorum attached to a wallet on another chain
// would pass it, and the enclave only signs EVM transactions.
func TestAccountForWallet_RejectsANonEthereumWallet(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount(resolveExternalID)},
	}
	cli := newResolveClient(t, state)

	wallet := walletOneObject()
	wallet.ChainType = "solana"

	account, httpErr := cli.accountForWallet(walletTestPrivyID, resolveExternalID, wallet)
	if httpErr == nil {
		t.Fatalf("accountForWallet() returned %+v, want a non-ethereum wallet to be rejected", account)
	}
}

// A purpose wallet has to be signable, which means the signing path must resolve an address
// that is nowhere on the user's record. Provisioning one and then being unable to sign with it
// would make the whole feature inert.
func TestResolveDelegatedWallet_ResolvesAPurposeWalletByAddress(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr != nil {
		t.Fatalf("resolveDelegatedWallet() error = %+v", httpErr)
	}

	// The wallet id is what the signing request is actually addressed to.
	if account.WalletID != "w1" {
		t.Errorf("WalletID = %q, want w1", account.WalletID)
	}
}

// The ownership check, and the reason the external id is checked rather than trusted. Resolving
// by address means an authenticated user can name any address in the app, so a wallet
// provisioned for someone else must be refused even though Privy resolves it happily and our
// own quorum is attached to it.
func TestResolveDelegatedWallet_RefusesAWalletProvisionedForAnotherUser(t *testing.T) {
	someoneElses := walletOneObject()
	someoneElses.ExternalID = "cm00000000000000000002-" + wealthPurpose

	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   someoneElses,
	}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedWallet() returned another user's wallet %+v, want a refusal", account)
	}
	if httpErr.Code != http.StatusBadRequest {
		t.Errorf("Code = %d, want 400", httpErr.Code)
	}
}

// A wallet with no external id at all is equally unattributable, and an app wallet that belongs
// to no user must not become signable just because it exists.
func TestResolveDelegatedWallet_RefusesAWalletWithNoExternalID(t *testing.T) {
	unattributed := walletOneObject()
	unattributed.ExternalID = ""

	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   unattributed,
	}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedWallet() returned unattributed wallet %+v, want a refusal", account)
	}
}

// Axal's quorum has to be attached, or the signature Privy is asked for would be refused there
// instead — after the enclave had already committed to the wallet.
func TestResolveDelegatedWallet_RefusesAWalletWithoutAxalsSigner(t *testing.T) {
	unsignable := walletOneObject()
	unsignable.AdditionalSigners = nil

	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   unsignable,
	}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedWallet() returned unsignable wallet %+v, want a refusal", account)
	}
}

// An address Privy does not know is refused rather than guessed at.
func TestResolveDelegatedWallet_RefusesAnUnknownAddress(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedWallet() returned %+v for an address Privy does not hold, want a refusal", account)
	}
	if httpErr.Code != http.StatusBadRequest {
		t.Errorf("Code = %d, want 400", httpErr.Code)
	}
}

// Signing is the hot path, so a resolved wallet is folded into the cached record: the second
// signature for the same wallet must not pay another lookup.
func TestResolveDelegatedWallet_CachesTheResolvedWallet(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	if _, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr); httpErr != nil {
		t.Fatalf("first resolveDelegatedWallet() error = %+v", httpErr)
	}
	lookups := atomic.LoadInt64(&state.lookupCount)

	if _, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr); httpErr != nil {
		t.Fatalf("second resolveDelegatedWallet() error = %+v", httpErr)
	}

	if got := atomic.LoadInt64(&state.lookupCount); got != lookups {
		t.Errorf("wallet lookups = %d, want %d: the resolved wallet was not cached", got, lookups)
	}
}

// The user's own embedded wallet is still resolved straight from the record. It is the common
// case and must not start costing a wallet lookup.
func TestResolveDelegatedWallet_ResolvesWalletZeroWithoutALookup(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletZeroAddr)
	if httpErr != nil {
		t.Fatalf("resolveDelegatedWallet() error = %+v", httpErr)
	}
	if account.WalletID != "w0" {
		t.Errorf("WalletID = %q, want w0", account.WalletID)
	}

	if got := atomic.LoadInt64(&state.lookupCount); got != 0 {
		t.Errorf("wallet lookups = %d, want 0 for a wallet already on the record", got)
	}
}
