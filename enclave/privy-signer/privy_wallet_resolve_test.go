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

// The lookup by external id resolves the wallet even when the user record does not carry the
// external id at all — which is the whole reason the lookup exists.
func TestFindWalletByExternalID_ResolvesWithoutTheEchoedExternalID(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
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

	if wallet.Address != walletOneAddr {
		t.Errorf("Address = %s, want %s", wallet.Address, walletOneAddr)
	}

	// Both fields come from the user record rather than the wallet object, which carries
	// neither. Losing them would make the wallet unsignable and misreport its index.
	if !wallet.Delegated {
		t.Error("resolved wallet is not delegated, so Axal could not sign with it")
	}
	if wallet.WalletIndex != 1 {
		t.Errorf("WalletIndex = %d, want 1", wallet.WalletIndex)
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

// Straight after a create the cached record predates the wallet, so a miss against it is
// expected rather than conclusive and has to be answered from Privy.
func TestFindWalletByExternalID_RefetchesWhenTheCachedRecordPredatesTheWallet(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	// Warm the cache with the pre-create record, as the create path itself does.
	if _, httpErr := cli.GetUser(walletTestPrivyID); httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}

	// The create lands: the wallet now exists and the user record carries it.
	state.setAccounts([]data.LinkedAccount{walletZeroAccount(), walletOneAccount("")})
	state.setWallet(walletOneObject())

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v", httpErr)
	}

	if wallet.Address != walletOneAddr {
		t.Errorf("Address = %s, want %s — the stale cached record was served instead of a refetch", wallet.Address, walletOneAddr)
	}
	if got := atomic.LoadInt64(&state.getCount); got != 2 {
		t.Errorf("user fetches = %d, want 2 (the warm-up and the refetch)", got)
	}
}

// The record the caller gets back is also the record the next signature resolves against, so
// resolving has to leave the cache agreeing with Privy.
func TestFindWalletByExternalID_LeavesTheCacheConsistent(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v", httpErr)
	}

	item := cli.userCache.Get(walletTestPrivyID)
	if item == nil {
		t.Fatal("user record is not cached after resolving a wallet")
	}

	cached := item.Value()
	if cached.GetEthDelegatedWalletByAddress(wallet.Address) == nil {
		t.Error("the resolved wallet is missing from the cached user record")
	}
	if cached.GetEthDelegatedWalletByAddress(walletZeroAddr) == nil {
		t.Error("wallet 0 was lost from the cached user record")
	}
}

// The account handed back is a copy. It is read out of a record whose LinkedAccounts slice
// shares its backing array with the cache entry, so returning a pointer into it would let any
// caller reach through and rewrite what every later signature resolves.
func TestFindWalletByExternalID_ReturnsACopyOfTheCachedAccount(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v", httpErr)
	}

	wallet.Address = "0xdead000000000000000000000000000000000000"

	cached := cli.userCache.Get(walletTestPrivyID).Value()
	if cached.GetEthDelegatedWalletByAddress(walletOneAddr) == nil {
		t.Error("mutating the returned wallet rewrote the cached user record")
	}
}

// A wallet Privy holds but does not list on the user is not usable: the signing path resolves
// addresses out of the user record, so returning it would hand back an address no signature
// could reach.
func TestFindWalletByExternalID_FailsWhenTheWalletIsNotOnTheUser(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr == nil {
		t.Fatalf("findWalletByExternalID() returned wallet %+v, want an error", wallet)
	}
	if httpErr.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", httpErr.Code)
	}
}

// Same wallet, listed on the user but not delegated. Axal-initiated signing would be refused
// for it, so it is rejected rather than returned.
func TestFindWalletByExternalID_FailsWhenTheUserWalletIsNotDelegated(t *testing.T) {
	undelegated := walletOneAccount(resolveExternalID)
	undelegated.Delegated = false

	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), undelegated},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr == nil {
		t.Fatalf("findWalletByExternalID() returned undelegated wallet %+v, want an error", wallet)
	}
	if httpErr.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", httpErr.Code)
	}
}

// The user record is the last source of truth, so its failure is the call's failure.
func TestFindWalletByExternalID_PropagatesAUserFetchFailure(t *testing.T) {
	state := &resolveServer{
		wallet:     walletOneObject(),
		userStatus: http.StatusInternalServerError,
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, resolveExternalID)
	if httpErr == nil {
		t.Fatalf("findWalletByExternalID() returned wallet %+v, want the user fetch failure", wallet)
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
