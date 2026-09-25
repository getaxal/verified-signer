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

// The lookup by external id identifies the wallet even when the user record does not carry
// the external id at all — which is the whole reason the lookup exists.
func TestResolveCreatedWallet_IdentifiesByExternalIDLookup(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr != nil {
		t.Fatalf("resolveCreatedWallet() error = %+v", httpErr)
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

// The production case. A replayed create returns only wallets the caller already knew, so
// the new wallet is in `known` and no response-based selection can ever pick it out. The
// lookup is what breaks the tie, and getting this wrong is a 500 no retry can clear.
func TestResolveCreatedWallet_IdentifiesAReplayedCreate(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	known := map[string]bool{"w0": true, "w1": true}

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, known)
	if httpErr != nil {
		t.Fatalf("resolveCreatedWallet() error = %+v, want the wallet the replayed create had already made", httpErr)
	}
	if wallet.Address != walletOneAddr {
		t.Errorf("Address = %s, want %s", wallet.Address, walletOneAddr)
	}
}

// With the lookup answering 404, the refetched user record has to carry the identification.
// The cached record cannot: it was read before the create, so it is answered from Privy or
// not at all.
func TestResolveCreatedWallet_FallsBackToTheRefetchedUser(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	// Warm the cache with the pre-create record, as the create path itself does.
	if _, httpErr := cli.GetUser(walletTestPrivyID); httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}

	// The create lands, and this time Privy does echo the external id back on the user.
	state.setAccounts([]data.LinkedAccount{walletZeroAccount(), walletOneAccount(resolveExternalID)})

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr != nil {
		t.Fatalf("resolveCreatedWallet() error = %+v", httpErr)
	}

	if wallet.Address != walletOneAddr {
		t.Errorf("Address = %s, want %s — the stale cached record was served instead of a refetch", wallet.Address, walletOneAddr)
	}
	if got := atomic.LoadInt64(&state.getCount); got != 2 {
		t.Errorf("user fetches = %d, want 2 (the warm-up and the refetch)", got)
	}
}

// Neither source names the external id, so the wallet is identified as the delegated eth
// wallet the user did not hold before the create. This is the only remaining signal, and it
// is unambiguous because a create makes exactly one wallet.
func TestResolveCreatedWallet_FallsBackToTheUnknownDelegatedWallet(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr != nil {
		t.Fatalf("resolveCreatedWallet() error = %+v", httpErr)
	}
	if wallet.Address != walletOneAddr {
		t.Errorf("Address = %s, want %s", wallet.Address, walletOneAddr)
	}
}

// The record the caller gets back is also the record the next signature resolves against,
// so resolving has to leave the cache agreeing with Privy.
func TestResolveCreatedWallet_LeavesTheCacheConsistent(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr != nil {
		t.Fatalf("resolveCreatedWallet() error = %+v", httpErr)
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

// The account the refetch path returns is a copy. That path selects straight out of the
// refetched record, whose LinkedAccounts slice shares its backing array with the cache
// entry, so handing back a pointer into it would let any caller reach through and rewrite
// what every later signature resolves.
//
// The lookup path cannot show this: it reads accounts out of a range copy and so hands back
// a copy either way. Identification here is left to the refetch — no wallet under the
// external id — which is the path where the copy is load bearing.
func TestResolveCreatedWallet_RefetchReturnsACopyOfTheCachedAccount(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr != nil {
		t.Fatalf("resolveCreatedWallet() error = %+v", httpErr)
	}

	wallet.Address = "0xdead000000000000000000000000000000000000"

	cached := cli.userCache.Get(walletTestPrivyID).Value()
	if cached.GetEthDelegatedWalletByAddress(walletOneAddr) == nil {
		t.Error("mutating the returned wallet rewrote the cached user record")
	}
}

// Nothing identifies the wallet: the lookup finds none and every wallet on the user was
// already known. Guessing here would hand back a wallet that may hold someone else's money,
// so the call fails.
func TestResolveCreatedWallet_FailsWhenNothingIdentifiesTheWallet(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr == nil {
		t.Fatalf("resolveCreatedWallet() returned wallet %+v, want an error", wallet)
	}
	if httpErr.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", httpErr.Code)
	}
}

// A wallet found by external id still has to be delegated on ethereum. One that is not
// would serve user-initiated signing and fail every Axal-initiated one, so it is rejected
// rather than returned.
func TestResolveCreatedWallet_RejectsAWalletThatIsNotDelegated(t *testing.T) {
	undelegated := walletOneAccount(resolveExternalID)
	undelegated.Delegated = false

	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount(), undelegated}}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr == nil {
		t.Fatalf("resolveCreatedWallet() returned undelegated wallet %+v, want an error", wallet)
	}
	if httpErr.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", httpErr.Code)
	}
}

// A lookup that fails is not a lookup that found nothing. Treating the two alike would read
// a Privy outage as "no wallet exists" and let the caller create a second one.
func TestResolveCreatedWallet_PropagatesALookupFailure(t *testing.T) {
	state := &resolveServer{
		accounts:     []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		lookupStatus: http.StatusInternalServerError,
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr == nil {
		t.Fatalf("resolveCreatedWallet() returned wallet %+v, want the lookup failure", wallet)
	}
	if got := atomic.LoadInt64(&state.getCount); got != 0 {
		t.Errorf("user fetches = %d, want 0: a failed lookup must not be answered by guessing from the user record", got)
	}
}

// The refetch is the last source of truth, so its failure is the call's failure.
func TestResolveCreatedWallet_PropagatesAUserFetchFailure(t *testing.T) {
	state := &resolveServer{userStatus: http.StatusInternalServerError}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.resolveCreatedWallet(walletTestPrivyID, resolveExternalID, map[string]bool{"w0": true})
	if httpErr == nil {
		t.Fatalf("resolveCreatedWallet() returned wallet %+v, want the user fetch failure", wallet)
	}
}
