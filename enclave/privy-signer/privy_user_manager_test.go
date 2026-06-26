package privysigner

import (
	"encoding/json"
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

const testRacePrivyID = "did:privy:concurrencytest0001"

// walletlessUserJSON returns a Privy user with NO delegated eth wallet, forcing
// createUserWalletsIfNotExists down the create-wallet POST path.
func walletlessUserJSON(id string) string {
	user := data.PrivyUser{
		PrivyID: id,
		LinkedAccounts: []data.LinkedAccount{
			{Type: "email", Address: "test@example.com"},
		},
	}
	b, _ := json.Marshal(user)
	return string(b)
}

// delegatedWalletResponseJSON returns a create-wallet response containing a
// delegated ethereum wallet, mirroring what Privy returns on success.
func delegatedWalletResponseJSON() string {
	resp := data.CreateWalletResponse{
		ID: "wallet_created_1",
		LinkedAccounts: []*data.LinkedAccount{
			{
				WalletID:  "wallet_created_1",
				Type:      "wallet",
				ChainType: "ethereum",
				Address:   "0xabc0000000000000000000000000000000000001",
				Delegated: true,
			},
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// newTestPrivyClient builds a PrivyClient wired to a mock Privy HTTP server.
// getCount / postCount let tests assert exactly how many times each Privy
// endpoint was hit. A configurable delay on the GET widens the race window so
// concurrent callers reliably overlap inside the (former) check-then-create gap.
func newTestPrivyClient(t *testing.T, getDelay time.Duration) (*PrivyClient, *int64, *int64) {
	t.Helper()

	var getCount, postCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/users/") && !strings.HasSuffix(r.URL.Path, "/wallets"):
			atomic.AddInt64(&getCount, 1)
			if getDelay > 0 {
				time.Sleep(getDelay)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(walletlessUserJSON(testRacePrivyID)))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wallets"):
			atomic.AddInt64(&postCount, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(delegatedWalletResponseJSON()))

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	cache := ttlcache.New(
		ttlcache.WithTTL[string, data.PrivyUser](30*time.Minute),
		ttlcache.WithCapacity[string, data.PrivyUser](1000),
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

	return cli, &getCount, &postCount
}

// TestGetUser_ConcurrentFirstTime_CreatesAtMostOneWallet fires N concurrent
// first-time GetUser calls for the SAME privyId against a mocked Privy layer and
// asserts the create-wallet POST is invoked AT MOST ONCE. Without the per-privyId
// singleflight guard, every goroutine would miss the cache, GET a wallet-less
// user, pass the createUserWalletsIfNotExists check, and POST -> N wallets.
func TestGetUser_ConcurrentFirstTime_CreatesAtMostOneWallet(t *testing.T) {
	const n = 50

	// Delay the GET so all N goroutines are guaranteed to overlap in the window.
	cli, getCount, postCount := newTestPrivyClient(t, 100*time.Millisecond)

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]*data.PrivyUser, n)
	errs := make([]*data.HttpError, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // barrier: release all goroutines at once
			user, httpErr := cli.GetUser(testRacePrivyID)
			results[idx] = user
			errs[idx] = httpErr
		}(i)
	}

	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(postCount); got != 1 {
		t.Fatalf("create-wallet POST count = %d, want exactly 1", got)
	}

	if got := atomic.LoadInt64(getCount); got != 1 {
		t.Errorf("GET user count = %d, want exactly 1 (calls should collapse)", got)
	}

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d got error: %+v", i, errs[i])
			continue
		}
		if results[i] == nil {
			t.Errorf("goroutine %d got nil user", i)
			continue
		}
		if results[i].GetUsersEthDelegatedWallet() == nil {
			t.Errorf("goroutine %d: user is missing delegated eth wallet", i)
		}
	}
}

// TestGetUser_RepeatedCallsAfterSuccess_HitCache verifies that once a wallet has
// been created and cached, subsequent sequential calls serve from cache and issue
// no further GET or POST to Privy.
func TestGetUser_RepeatedCallsAfterSuccess_HitCache(t *testing.T) {
	cli, getCount, postCount := newTestPrivyClient(t, 0)

	user, httpErr := cli.GetUser(testRacePrivyID)
	if httpErr != nil {
		t.Fatalf("first GetUser errored: %+v", httpErr)
	}
	if user == nil || user.GetUsersEthDelegatedWallet() == nil {
		t.Fatal("first GetUser returned no delegated wallet")
	}

	for i := 0; i < 10; i++ {
		if _, err := cli.GetUser(testRacePrivyID); err != nil {
			t.Fatalf("cached GetUser %d errored: %+v", i, err)
		}
	}

	if got := atomic.LoadInt64(getCount); got != 1 {
		t.Errorf("GET user count = %d, want 1 (subsequent calls must hit cache)", got)
	}
	if got := atomic.LoadInt64(postCount); got != 1 {
		t.Errorf("create-wallet POST count = %d, want 1", got)
	}
}

// TestGetUser_ErrorIsNotCached confirms that a failed create-wallet does NOT
// poison the cache: the next call must re-enter the fetch path and retry rather
// than returning a cached failure or skipping the lock.
func TestGetUser_ErrorIsNotCached(t *testing.T) {
	var getCount, postCount int64
	failPost := int64(1) // first POST fails, subsequent ones succeed

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && !strings.HasSuffix(r.URL.Path, "/wallets"):
			atomic.AddInt64(&getCount, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(walletlessUserJSON(testRacePrivyID)))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wallets"):
			atomic.AddInt64(&postCount, 1)
			if atomic.CompareAndSwapInt64(&failPost, 1, 0) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"privy boom"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(delegatedWalletResponseJSON()))

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	cache := ttlcache.New(
		ttlcache.WithTTL[string, data.PrivyUser](30*time.Minute),
		ttlcache.WithCapacity[string, data.PrivyUser](1000),
	)
	cli := &PrivyClient{
		Environment: "test",
		baseUrl:     server.URL,
		client:      server.Client(),
		teeConfig: &enclave.TEEConfig{
			Privy: enclave.PrivyConfig{DelegatedActionsKeyId: "test-signer-id"},
		},
		userCache: cache,
	}

	// First call fails at the create-wallet step.
	if _, httpErr := cli.GetUser(testRacePrivyID); httpErr == nil {
		t.Fatal("expected first GetUser to error from failing POST")
	}

	// The failure must NOT have been cached: a retry should re-fetch and succeed.
	user, httpErr := cli.GetUser(testRacePrivyID)
	if httpErr != nil {
		t.Fatalf("retry after failure errored (error was cached?): %+v", httpErr)
	}
	if user == nil || user.GetUsersEthDelegatedWallet() == nil {
		t.Fatal("retry did not return a delegated wallet")
	}

	if got := atomic.LoadInt64(&getCount); got != 2 {
		t.Errorf("GET user count = %d, want 2 (retry must re-fetch, not serve cached error)", got)
	}
	if got := atomic.LoadInt64(&postCount); got != 2 {
		t.Errorf("create-wallet POST count = %d, want 2 (one failed + one successful retry)", got)
	}
}
