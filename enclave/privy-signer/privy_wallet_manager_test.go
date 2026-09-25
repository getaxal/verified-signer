package privysigner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/jellydator/ttlcache/v3"
)

const (
	walletTestPrivyID = "did:privy:cm00000000000000000001"
	walletZeroAddr    = "0xaaaa000000000000000000000000000000000001"
	walletOneAddr     = "0xbbbb000000000000000000000000000000000002"
	wealthPurpose     = "wealth_plan"
)

// walletProvisioningServer mocks the Privy endpoints the create path touches.
//
// It is stateful, because the behaviour under test only exists across calls: a created
// wallet is visible to later GETs, and every POST to /wallets mints a NEW wallet. Privy
// does not suppress duplicates for us, so any suppression has to come from our side.
type walletProvisioningServer struct {
	mu           sync.Mutex
	created      []data.LinkedAccount
	getCount     int64
	postCount    int64
	lookupCount  int64
	idemKeys     []string
	externalIDs  []string
	seenIdemKeys map[string]bool

	// Mirrors a Privy that does not echo our external id back inside linked_accounts, and
	// that replays an earlier response when it sees an idempotency key again. Neither is
	// something the happy-path mock can express, and together they are what the enclave met
	// in production. Set before the first request.
	suppressExternalID bool
	replayIdempotency  bool

	// Non-zero to answer the create with this status after minting the wallet, standing for a
	// create that landed and then failed on the way back — or for the cached error Privy
	// replays against the same idempotency key for the next 24 hours.
	createStatus int

	// Set alongside createStatus to fail without minting, standing for a create that never
	// landed at all.
	suppressCreate bool
}

func (s *walletProvisioningServer) linkedAccounts() []data.LinkedAccount {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.linkedAccountsLocked()
}

// The account set as Privy would render it, which is not the same as the set the mock
// holds: `created` keeps every external id so a lookup by external id can still resolve,
// while the rendered copy hides it when the mock is standing in for a Privy that does not
// echo it.
func (s *walletProvisioningServer) linkedAccountsLocked() []data.LinkedAccount {
	accounts := []data.LinkedAccount{{
		WalletID: "w0", Type: "wallet", Address: walletZeroAddr,
		ChainType: "ethereum", Delegated: true, WalletIndex: 0,
	}}

	for _, acc := range s.created {
		if s.suppressExternalID {
			acc.ExternalID = ""
		}
		accounts = append(accounts, acc)
	}

	return accounts
}

// Mints a wallet and returns it as the wallet API does, which is a wallet object rather than
// the user. A repeated idempotency key replays the wallet the first call made.
func (s *walletProvisioningServer) mint(externalID string, idemKey string) *data.PrivyWallet {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.idemKeys = append(s.idemKeys, idemKey)
	s.externalIDs = append(s.externalIDs, externalID)

	if s.replayIdempotency && s.seenIdemKeys[idemKey] {
		for _, acc := range s.created {
			if acc.ExternalID == externalID {
				return walletObject(acc)
			}
		}
	}
	s.seenIdemKeys[idemKey] = true

	n := len(s.created) + 1
	acc := data.LinkedAccount{
		WalletID:  fmt.Sprintf("w%d", n),
		Type:      "wallet",
		Address:   fmt.Sprintf("0xbbbb00000000000000000000000000000000000%d", n),
		ChainType: "ethereum", Delegated: true, WalletIndex: n,
		ExternalID: externalID,
	}
	s.created = append(s.created, acc)

	return walletObject(acc)
}

// The same wallet as Privy's wallet endpoints render it: signers attached, and no
// wallet_index or delegated flag, because a wallet object carries neither.
func walletObject(acc data.LinkedAccount) *data.PrivyWallet {
	return &data.PrivyWallet{
		ID:         acc.WalletID,
		Address:    acc.Address,
		ChainType:  acc.ChainType,
		ExternalID: acc.ExternalID,
		AdditionalSigners: []*data.AdditionalSigner{
			{SignerID: "test-signer-id"},
		},
	}
}

// Resolves Privy's ext_wal_<external id> wallet reference, or nil when no wallet carries it.
func (s *walletProvisioningServer) walletByRef(ref string) *data.PrivyWallet {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, acc := range s.created {
		if acc.ExternalID == "" || data.ExternalWalletRef(acc.ExternalID) != ref {
			continue
		}

		return &data.PrivyWallet{
			ID:         acc.WalletID,
			Address:    acc.Address,
			ChainType:  acc.ChainType,
			ExternalID: acc.ExternalID,
			AdditionalSigners: []*data.AdditionalSigner{
				{SignerID: "test-signer-id"},
			},
		}
	}

	return nil
}

func newWalletProvisioningClient(t *testing.T, getDelay time.Duration) (*PrivyClient, *walletProvisioningServer) {
	t.Helper()

	state := &walletProvisioningServer{seenIdemKeys: map[string]bool{}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/users/"):
			atomic.AddInt64(&state.getCount, 1)
			if getDelay > 0 {
				time.Sleep(getDelay)
			}
			b, _ := json.Marshal(data.PrivyUser{
				PrivyID:        walletTestPrivyID,
				LinkedAccounts: state.linkedAccounts(),
			})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/wallets/"):
			atomic.AddInt64(&state.lookupCount, 1)

			wallet := state.walletByRef(strings.TrimPrefix(r.URL.Path, "/v1/wallets/"))
			if wallet == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"wallet not found"}`))
				return
			}

			b, _ := json.Marshal(wallet)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodPost && r.URL.Path == "/v1/wallets":
			atomic.AddInt64(&state.postCount, 1)

			var body data.CreateWalletForOwnerRequest
			_ = json.NewDecoder(r.Body).Decode(&body)

			// Owner and additional signer are what make the wallet the user's and signable by
			// Axal. A create missing either is not the call the enclave means to make, whatever
			// it returns.
			if body.Owner == nil || body.Owner.UserID != walletTestPrivyID {
				t.Errorf("create wallet owner = %+v, want user %s", body.Owner, walletTestPrivyID)
			}
			if len(body.AdditionalSigners) != 1 || body.AdditionalSigners[0].SignerID != "test-signer-id" {
				t.Errorf("create wallet additional_signers = %+v, want the delegated actions quorum", body.AdditionalSigners)
			}
			if body.ChainType != "ethereum" {
				t.Errorf("create wallet chain_type = %q, want ethereum", body.ChainType)
			}

			var wallet *data.PrivyWallet
			if !state.suppressCreate {
				wallet = state.mint(body.ExternalID, r.Header.Get("privy-idempotency-key"))
			}

			if status := state.createStatus; status != 0 {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"create failed"}`))
				return
			}

			b, _ := json.Marshal(wallet)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		// The user-scoped create only provisions the wallet at HD index 0. Every user in
		// these tests already has one, so reaching it means the enclave asked the wrong
		// endpoint for an additional wallet.
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wallets"):
			t.Errorf("additional wallet requested from the user-scoped create endpoint: %s", r.URL.Path)
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

	cli := &PrivyClient{
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

	return cli, state
}

// The wallet must come back delegated and on ethereum. A wallet created without our
// signer attached would serve user-initiated signing and fail every Axal-initiated one.
func TestCreateUserWallet_ReturnsADelegatedEthWallet(t *testing.T) {
	cli, _ := newWalletProvisioningClient(t, 0)

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}
	if !wallet.Delegated {
		t.Error("created wallet is not delegated")
	}
	if wallet.ChainType != "ethereum" {
		t.Errorf("ChainType = %v, want ethereum", wallet.ChainType)
	}
	if wallet.Address == walletZeroAddr {
		t.Error("returned wallet 0 instead of the newly created wallet")
	}
	if wallet.WalletIndex == 0 {
		t.Error("returned the wallet at HD index 0 instead of the new one")
	}
}

// Asking twice must return the same address and leave exactly one new wallet behind. A
// duplicate here is an address that may already have received money.
func TestCreateUserWallet_IsIdempotentForAPurpose(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)

	first, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("first CreateUserWallet() error = %+v", httpErr)
	}

	second, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("second CreateUserWallet() error = %+v", httpErr)
	}

	if first.Address != second.Address {
		t.Errorf("addresses differ across calls: %s then %s", first.Address, second.Address)
	}
	if got := atomic.LoadInt64(&state.postCount); got != 1 {
		t.Errorf("create-wallet POSTs = %d, want 1", got)
	}
}

// Concurrent callers for the same user and purpose must collapse into one create.
func TestCreateUserWallet_ConcurrentCallsCreateOneWallet(t *testing.T) {
	const n = 25

	cli, state := newWalletProvisioningClient(t, 50*time.Millisecond)

	var wg sync.WaitGroup
	addrs := make([]string, n)
	errs := make([]*data.HttpError, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
			errs[i] = httpErr
			if wallet != nil {
				addrs[i] = wallet.Address
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: CreateUserWallet() error = %+v", i, err)
		}
	}
	for i, addr := range addrs {
		if addr != addrs[0] {
			t.Errorf("goroutine %d got address %s, want %s", i, addr, addrs[0])
		}
	}
	if got := atomic.LoadInt64(&state.postCount); got != 1 {
		t.Errorf("create-wallet POSTs = %d, want 1", got)
	}
}

// The guards that survive outside this process: a stable external id and a deterministic
// idempotency key. These are what cover a second enclave instance or a caller that
// redialled, which the singleflight group cannot see.
func TestCreateUserWallet_SendsStableIdempotencyGuards(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)

	if _, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose); httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	wantExternal := "cm00000000000000000001-" + wealthPurpose
	if len(state.externalIDs) != 1 || state.externalIDs[0] != wantExternal {
		t.Errorf("external ids = %v, want [%s]", state.externalIDs, wantExternal)
	}
	if len(state.idemKeys) != 1 || state.idemKeys[0] != "wallet-create:"+wantExternal {
		t.Errorf("idempotency keys = %v, want [wallet-create:%s]", state.idemKeys, wantExternal)
	}
}

// The signing path resolves addresses against the cached user, so a wallet created here
// has to be visible to the very next signature rather than after the cache TTL.
func TestCreateUserWallet_NewWalletIsImmediatelyResolvable(t *testing.T) {
	cli, _ := newWalletProvisioningClient(t, 0)

	// Warm the cache with the pre-creation user, as a signature would.
	if _, httpErr := cli.GetUser(walletTestPrivyID); httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}

	if _, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, wallet.Address); httpErr != nil {
		t.Errorf("newly created wallet is not resolvable for signing: %+v", httpErr)
	}
}

func TestCreateUserWallet_RejectsBadPurpose(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)

	for _, purpose := range []string{"", "Wealth_Plan", "wealth plan", "wealth.plan", strings.Repeat("a", 40)} {
		t.Run(purpose, func(t *testing.T) {
			_, httpErr := cli.CreateUserWallet(walletTestPrivyID, purpose)
			if httpErr == nil {
				t.Fatalf("CreateUserWallet(%q) succeeded, want rejection", purpose)
			}
			if httpErr.Code != http.StatusBadRequest {
				t.Errorf("Code = %d, want 400", httpErr.Code)
			}
		})
	}

	if got := atomic.LoadInt64(&state.postCount); got != 0 {
		t.Errorf("create-wallet POSTs = %d, want 0", got)
	}
}

// A create that returns 200 without naming the new wallet must not fail: Privy has created
// it, and the enclave has to find out which wallet it is rather than report a failure the
// caller cannot retry away.
//
// This is the production failure. With external ids absent from linked_accounts, the first
// create succeeds but every later call for the same purpose reads a user it cannot
// recognise the wallet on, then gets back an idempotent replay carrying only wallets it
// already knew — so the wallet exists, is funded, and is unreachable, for as long as the
// idempotency record lives.
func TestCreateUserWallet_RecoversWhenExternalIDIsNotEchoed(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)
	state.suppressExternalID = true
	state.replayIdempotency = true

	first, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("first CreateUserWallet() error = %+v", httpErr)
	}

	second, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("second CreateUserWallet() error = %+v, want the wallet the first call created", httpErr)
	}

	if first.Address != second.Address {
		t.Errorf("addresses differ across calls: %s then %s", first.Address, second.Address)
	}

	state.mu.Lock()
	createdWallets := len(state.created)
	state.mu.Unlock()

	if createdWallets != 1 {
		t.Errorf("wallets minted = %d, want 1", createdWallets)
	}
}

// The wallet a lookup by external id resolves to still has to be usable for signing, which
// is resolved out of the user record by address.
func TestCreateUserWallet_ExternalIDLookupReturnsASignableWallet(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)
	state.suppressExternalID = true
	state.replayIdempotency = true

	if _, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose); httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v", httpErr)
	}

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("second CreateUserWallet() error = %+v", httpErr)
	}

	if !wallet.Delegated {
		t.Error("wallet resolved by external id is not delegated, so Axal cannot sign with it")
	}
	if wallet.WalletIndex == 0 {
		t.Error("wallet resolved by external id lost its HD index")
	}
	if _, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, wallet.Address); httpErr != nil {
		t.Errorf("wallet resolved by external id is not signable: %+v", httpErr)
	}
}

// A create that fails may still have created the wallet, and Privy caches 4xx and 5xx
// responses against the idempotency key and replays them for 24 hours. Reporting the failure
// without looking would strand a wallet that exists and leave every retry answered by the
// same cached error — so the wallet is looked up before the error is believed.
func TestCreateUserWallet_RecoversWhenACreateErrorHidesASuccess(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)
	state.createStatus = http.StatusInternalServerError

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr != nil {
		t.Fatalf("CreateUserWallet() error = %+v, want the wallet the failed create had already made", httpErr)
	}

	if wallet.Address == walletZeroAddr {
		t.Errorf("Address = %s, want the newly created wallet rather than wallet 0", wallet.Address)
	}
	if !wallet.Delegated {
		t.Error("recovered wallet is not delegated, so Axal could not sign with it")
	}
}

// The same failure with nothing behind it stays a failure. Recovering from an error must mean
// finding the wallet, never assuming one.
func TestCreateUserWallet_ReportsACreateFailureWithNothingBehindIt(t *testing.T) {
	cli, state := newWalletProvisioningClient(t, 0)
	state.createStatus = http.StatusInternalServerError
	state.suppressCreate = true

	wallet, httpErr := cli.CreateUserWallet(walletTestPrivyID, wealthPurpose)
	if httpErr == nil {
		t.Fatalf("CreateUserWallet() returned %+v, want the create failure", wallet)
	}
}
