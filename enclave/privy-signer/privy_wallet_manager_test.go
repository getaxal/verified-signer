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
	mu          sync.Mutex
	created     []data.LinkedAccount
	getCount    int64
	postCount   int64
	idemKeys    []string
	externalIDs []string
}

func (s *walletProvisioningServer) linkedAccounts() []data.LinkedAccount {
	s.mu.Lock()
	defer s.mu.Unlock()

	accounts := []data.LinkedAccount{{
		WalletID: "w0", Type: "wallet", Address: walletZeroAddr,
		ChainType: "ethereum", Delegated: true, WalletIndex: 0,
	}}
	return append(accounts, s.created...)
}

// Mints a new wallet unconditionally, mirroring Privy's create-next behaviour.
func (s *walletProvisioningServer) mint(externalID string) []data.LinkedAccount {
	s.mu.Lock()
	n := len(s.created) + 1
	s.created = append(s.created, data.LinkedAccount{
		WalletID:  fmt.Sprintf("w%d", n),
		Type:      "wallet",
		Address:   fmt.Sprintf("0xbbbb00000000000000000000000000000000000%d", n),
		ChainType: "ethereum", Delegated: true, WalletIndex: n,
		ExternalID: externalID,
	})
	s.mu.Unlock()

	return s.linkedAccounts()
}

func newWalletProvisioningClient(t *testing.T, getDelay time.Duration) (*PrivyClient, *walletProvisioningServer) {
	t.Helper()

	state := &walletProvisioningServer{}

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

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wallets"):
			atomic.AddInt64(&state.postCount, 1)

			var body data.CreateWalletRequest
			_ = json.NewDecoder(r.Body).Decode(&body)

			externalID := ""
			if len(body.PrivyWalletCreateRequestWallets) > 0 {
				externalID = body.PrivyWalletCreateRequestWallets[0].ExternalID
			}

			state.mu.Lock()
			state.idemKeys = append(state.idemKeys, r.Header.Get("privy-idempotency-key"))
			state.externalIDs = append(state.externalIDs, externalID)
			state.mu.Unlock()

			accounts := state.mint(externalID)
			resp := data.CreateWalletResponse{ID: "created"}
			for i := range accounts {
				resp.LinkedAccounts = append(resp.LinkedAccounts, &accounts[i])
			}

			b, _ := json.Marshal(resp)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

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
