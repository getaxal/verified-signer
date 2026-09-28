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

	// The user Privy attributes `wallet` to. Defaults to the test user; set it to someone else
	// to stand for an address that is not this caller's to sign with.
	walletOwner string

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

// The user record a caller would be holding: what the mock's GET would return.
func recordOf(state *resolveServer) *data.PrivyUser {
	accounts, _, _, _ := state.snapshot()

	return &data.PrivyUser{PrivyID: walletTestPrivyID, LinkedAccounts: accounts}
}

// The user the mock attributes its wallet to, defaulting to the test user.
func (s *resolveServer) owner() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.walletOwner == "" {
		return walletTestPrivyID
	}

	return s.walletOwner
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

		owner := state.owner()

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

		case r.Method == http.MethodGet && r.URL.Path == "/v1/wallets":
			atomic.AddInt64(&state.lookupCount, 1)

			if lookupStatus != 0 {
				w.WriteHeader(lookupStatus)
				_, _ = w.Write([]byte(`{"error":"wallet list failed"}`))
				return
			}

			// Honours user_id the way Privy does: a wallet is listed only under the user whose
			// ownership quorum holds it. That is the ownership answer the signing path relies on,
			// so the mock has to be able to withhold it.
			listed := []*data.PrivyWallet{}
			if wallet != nil && r.URL.Query().Get("user_id") == owner {
				if addr := r.URL.Query().Get("address"); addr == "" || strings.EqualFold(addr, wallet.Address) {
					listed = append(listed, wallet)
				}
			}

			b, _ := json.Marshal(data.WalletListResponse{Data: listed})
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

// A wallet created this way is a real embedded wallet and lands on the user's record at the next
// HD index, so that is where its index and delegated flag must come from — the wallet object
// carries neither.
func TestFindWalletByExternalID_TakesTheIndexFromTheUserRecord(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), walletOneAccount("")},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, recordOf(state), resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v", httpErr)
	}
	if wallet == nil {
		t.Fatal("findWalletByExternalID() = nil, want the wallet Privy holds under the external id")
	}

	if wallet.WalletID != "w1" {
		t.Errorf("WalletID = %q, want w1 — the id is what signing addresses", wallet.WalletID)
	}
	if wallet.WalletIndex != 1 {
		t.Errorf("WalletIndex = %d, want 1 from the user record", wallet.WalletIndex)
	}
	if !wallet.Delegated {
		t.Error("resolved wallet is not delegated, so the signing path would refuse it")
	}

	// Privy does not echo external ids inside linked_accounts, so it has to be carried over
	// from the wallet object — without it the cached record cannot recognise this wallet on a
	// repeat provisioning call.
	if wallet.ExternalID != resolveExternalID {
		t.Errorf("ExternalID = %q, want %q carried over from the wallet object", wallet.ExternalID, resolveExternalID)
	}

	// The record handed in already carried the wallet, which is the case on every repeat call.
	// Rereading it would be a second GET for something already in hand, and would throw away a
	// cache entry filled moments earlier.
	if got := atomic.LoadInt64(&state.getCount); got != 0 {
		t.Errorf("user fetches = %d, want 0 when the record in hand already carries the wallet", got)
	}
}

// The user record is eventually consistent: a wallet has been seen to be missing from it for
// longer than the request that created it. Resolution must not fail in that window — the wallet
// exists, may be funded, and is signable — so the wallet object stands in.
func TestFindWalletByExternalID_ResolvesBeforeTheRecordCatchesUp(t *testing.T) {
	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   walletOneObject(),
	}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, recordOf(state), resolveExternalID)
	if httpErr != nil {
		t.Fatalf("findWalletByExternalID() error = %+v, want the wallet despite the lagging record", httpErr)
	}

	if wallet.WalletID != "w1" || wallet.Address != walletOneAddr {
		t.Errorf("resolved %q at %s, want w1 at %s", wallet.WalletID, wallet.Address, walletOneAddr)
	}

	// Asserted against the literal rather than against unknownWalletIndex, which would compare
	// the constant with itself and hold for any value it was given — including the one value it
	// must never be. Zero names the user's primary wallet, so reporting it here would point a
	// caller at the wrong wallet.
	if wallet.WalletIndex == 0 {
		t.Error("WalletIndex = 0, which names the user's primary wallet rather than this one")
	}
	if wallet.WalletIndex != -1 {
		t.Errorf("WalletIndex = %d, want -1 for an index the record has not supplied yet", wallet.WalletIndex)
	}
	if !wallet.Delegated {
		t.Error("wallet is not marked delegated, so the signing path would refuse it")
	}

	// The other side of that optimisation: a record that cannot answer must still be reread,
	// because only a reread can see a wallet created after the record was taken.
	if got := atomic.LoadInt64(&state.getCount); got != 1 {
		t.Errorf("user fetches = %d, want 1 reread when the record in hand lacks the wallet", got)
	}
}

// No wallet under the external id is an answer, not a failure: it is what tells the caller
// this purpose has never been provisioned and a create is due.
func TestFindWalletByExternalID_ReturnsNilWhenNoWalletExists(t *testing.T) {
	state := &resolveServer{accounts: []data.LinkedAccount{walletZeroAccount()}}
	cli := newResolveClient(t, state)

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, recordOf(state), resolveExternalID)
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

	wallet, httpErr := cli.findWalletByExternalID(walletTestPrivyID, recordOf(state), resolveExternalID)
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

			account, httpErr := cli.accountForWallet(walletTestPrivyID, recordOf(state), resolveExternalID, wallet)
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

	account, httpErr := cli.accountForWallet(walletTestPrivyID, recordOf(state), resolveExternalID, wallet)
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

// The ownership check. Resolving by address means an authenticated user can name any address in
// the app, so the question "is this wallet theirs" is put to Privy, scoped to this user. A wallet
// Privy does not attribute to them must be refused even though it exists and our own quorum is
// attached to it.
func TestResolveDelegatedWallet_RefusesAWalletPrivyDoesNotAttributeToTheUser(t *testing.T) {
	state := &resolveServer{
		accounts:    []data.LinkedAccount{walletZeroAccount()},
		wallet:      walletOneObject(),
		walletOwner: "did:privy:cm00000000000000000002",
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

// Defence in depth behind that check, and independent of Privy's filter behaving: a wallet
// carrying an external id must carry one of this user's. If the filter ever widened, this still
// refuses another user's purpose wallet.
func TestResolveDelegatedWallet_RefusesAWalletCarryingAnotherUsersExternalID(t *testing.T) {
	someoneElses := walletOneObject()
	someoneElses.ExternalID = "cm00000000000000000002-" + wealthPurpose

	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   someoneElses,
	}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedWallet() returned a wallet with another user's external id %+v, want a refusal", account)
	}
}

// A wallet with no external id is not thereby unusable. The user's own wallet 0 carries none, so
// requiring one would refuse it whenever it had to be resolved this way — which is what an
// earlier version of this check did.
func TestResolveDelegatedWallet_AcceptsAWalletWithNoExternalID(t *testing.T) {
	embedded := walletOneObject()
	embedded.ExternalID = ""

	state := &resolveServer{
		accounts: []data.LinkedAccount{walletZeroAccount()},
		wallet:   embedded,
	}
	cli := newResolveClient(t, state)

	account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletOneAddr)
	if httpErr != nil {
		t.Fatalf("resolveDelegatedWallet() error = %+v, want the user's own wallet to resolve", httpErr)
	}
	if account.WalletID != "w1" {
		t.Errorf("WalletID = %q, want w1", account.WalletID)
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
