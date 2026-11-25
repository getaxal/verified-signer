package privysigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"
)

const (
	// The test user's embedded solana wallet, and an address that is nobody's in these tests.
	solWalletAddr = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
	solOtherAddr  = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T"

	solTestSecret = "test-axal-request-secret"

	// What the mock answers a signing request with.
	solSignedTx = "c2lnbmVkLXRyYW5zYWN0aW9u"
)

// A transaction as a caller sends it. The enclave does not parse it, so its content only has
// to be base64.
var solTestTx = base64.StdEncoding.EncodeToString([]byte("a serialized solana transaction"))

// The user's embedded solana wallet as the user record carries it once it is delegated.
func solWalletAccount() data.LinkedAccount {
	return data.LinkedAccount{
		WalletID: "wsol0", Type: "wallet", Address: solWalletAddr,
		ChainType: "solana", Delegated: true, WalletIndex: 0,
		WalletClientType: "privy", ConnectorType: "embedded",
	}
}

// The same wallet as the wallet endpoint returns it: signers attached, no delegated flag.
func solWalletObject() *data.PrivyWallet {
	return &data.PrivyWallet{
		ID:        "wsol0",
		Address:   solWalletAddr,
		ChainType: "solana",
		AdditionalSigners: []*data.AdditionalSigner{
			{SignerID: "test-signer-id"},
		},
	}
}

func emailAccount() data.LinkedAccount {
	return data.LinkedAccount{Type: "email", Address: "user@example.com"}
}

// solServer mocks the Privy endpoints the solana paths touch: the user record, the embedded
// wallet create, the wallet list the resolver falls back to, and the signing RPC.
type solServer struct {
	mu sync.Mutex

	// The user record Privy serves. A successful create appends to it, so later reads see
	// the wallet the way they would at Privy.
	accounts []data.LinkedAccount

	// Non-zero to fail the solana create with this status, minting nothing.
	createStatus int

	// Mints the wallet without the delegated flag, standing for a create that ignored the
	// signer it was asked to attach.
	createUndelegated bool

	// The wallet the list endpoint resolves, and the user Privy attributes it to (the test
	// user when empty).
	wallet      *data.PrivyWallet
	walletOwner string

	// Overrides for the signing RPC's answer.
	rpcStatus   int
	rpcResponse string

	getCount    int64
	createCount int64
	listCount   int64
	rpcCount    int64

	// What the enclave actually sent.
	createPath string
	createBody data.CreateWalletRequest
	rpcPath    string
	rpcBody    string
	rpcAuthSig string
}

func (s *solServer) set(mutate func(*solServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	mutate(s)
}

type solTestClient struct {
	*PrivyClient
	state  *solServer
	jwtKey *ecdsa.PrivateKey
}

func newSolClient(t *testing.T, state *solServer) *solTestClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/users/"):
			atomic.AddInt64(&state.getCount, 1)

			b, _ := json.Marshal(data.PrivyUser{PrivyID: walletTestPrivyID, LinkedAccounts: state.accounts})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/users/") && strings.HasSuffix(r.URL.Path, "/wallets"):
			var body data.CreateWalletRequest
			_ = json.NewDecoder(r.Body).Decode(&body)

			// Every user here already holds an eth wallet, so the only create these tests can
			// legitimately cause is the solana one.
			if len(body.PrivyWalletCreateRequestWallets) != 1 || body.PrivyWalletCreateRequestWallets[0].ChainType != "solana" {
				t.Errorf("unexpected embedded wallet create: %+v", body)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			atomic.AddInt64(&state.createCount, 1)
			state.createPath = r.URL.Path
			state.createBody = body

			if state.createStatus != 0 {
				w.WriteHeader(state.createStatus)
				_, _ = w.Write([]byte(`{"error":"create failed"}`))
				return
			}

			minted := solWalletAccount()
			minted.Delegated = !state.createUndelegated
			state.accounts = append(state.accounts, minted)

			// The whole user, as Privy answers this endpoint — every account, not only the
			// wallet just made.
			b, _ := json.Marshal(data.PrivyUser{PrivyID: walletTestPrivyID, LinkedAccounts: state.accounts})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodGet && r.URL.Path == "/v1/wallets":
			atomic.AddInt64(&state.listCount, 1)

			owner := state.walletOwner
			if owner == "" {
				owner = walletTestPrivyID
			}

			// The address filter is looser than Privy's on purpose: it ignores case. That lets
			// a test hand the enclave a wallet at a different-case address and check that the
			// enclave's own comparison, not the filter, is what refuses it.
			listed := []*data.PrivyWallet{}
			if state.wallet != nil && r.URL.Query().Get("user_id") == owner &&
				strings.EqualFold(r.URL.Query().Get("address"), state.wallet.Address) {
				listed = append(listed, state.wallet)
			}

			b, _ := json.Marshal(data.WalletListResponse{Data: listed})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)

		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/wallets/") && strings.HasSuffix(r.URL.Path, "/rpc"):
			atomic.AddInt64(&state.rpcCount, 1)

			body, _ := io.ReadAll(r.Body)
			state.rpcPath = r.URL.Path
			state.rpcBody = string(body)
			state.rpcAuthSig = r.Header.Get("privy-authorization-signature")

			if state.rpcStatus != 0 {
				w.WriteHeader(state.rpcStatus)
				_, _ = w.Write([]byte(`{"error":"privy refused to sign"}`))
				return
			}

			response := state.rpcResponse
			if response == "" {
				response = `{"method":"signTransaction","data":{"signed_transaction":"` + solSignedTx + `","encoding":"base64"}}`
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	// The key the enclave signs Privy RPC requests with, in the form the config carries it.
	authorizationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate an authorization key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(authorizationKey)
	if err != nil {
		t.Fatalf("could not marshal the authorization key: %v", err)
	}

	// The key user JWTs are verified against.
	jwtKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a jwt key: %v", err)
	}
	jwtPublicKey, err := x509.MarshalPKIXPublicKey(&jwtKey.PublicKey)
	if err != nil {
		t.Fatalf("could not marshal the jwt public key: %v", err)
	}

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
			Environment: "local",
			Axal:        enclave.AxalConfig{AxalRequestSecretKey: solTestSecret},
			Privy: enclave.PrivyConfig{
				AppID:                 "test-app",
				DelegatedActionsKeyId: "test-signer-id",
				DelegatedActionsKey:   "wallet-auth:" + base64.StdEncoding.EncodeToString(pkcs8),
				JWTVerificationKey:    string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: jwtPublicKey})),
			},
		},
		userCache: cache,
	}

	return &solTestClient{PrivyClient: cli, state: state, jwtKey: jwtKey}
}

// A Privy access token for a user, signed with the key the client verifies against.
func (c *solTestClient) jwtFor(t *testing.T, privyID string) string {
	t.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": "test-app",
		"iss": "privy.io",
		"sub": privyID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(c.jwtKey)
	if err != nil {
		t.Fatalf("could not sign a test jwt: %v", err)
	}

	return token
}

// The HMAC a caller of the Axal route computes, written out from the documented preimage
// rather than through AuthPayload — so the test fails if the two ever drift apart.
func solHMAC(secret string, transaction string, walletAddress string, privyID string) string {
	digest := sha256.Sum256([]byte(transaction))
	preimage := "solana:signTransaction:base64:" + walletAddress + ":" + hex.EncodeToString(digest[:]) + ":" + privyID

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(preimage))

	return hex.EncodeToString(mac.Sum(nil))
}

func emailCount(user *data.PrivyUser) int {
	n := 0
	for _, acc := range user.LinkedAccounts {
		if acc.Type == "email" {
			n++
		}
	}
	return n
}

// The reason the read looks for a solana wallet at all: a user who has never had one gets it
// here, delegated, so the address is there to be signed with by the time anyone asks.
func TestGetUser_ProvisionsASolanaWalletForAUserWithoutOne(t *testing.T) {
	state := &solServer{accounts: []data.LinkedAccount{emailAccount(), walletZeroAccount()}}
	cli := newSolClient(t, state)

	user, httpErr := cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}

	wallet := user.GetUsersSolDelegatedWallet()
	if wallet == nil {
		t.Fatal("user came back without a delegated solana wallet")
	}
	if wallet.Address != solWalletAddr || wallet.WalletID != "wsol0" {
		t.Errorf("solana wallet = %s at %s, want wsol0 at %s", wallet.WalletID, wallet.Address, solWalletAddr)
	}
	if user.GetUsersEthDelegatedWallet() == nil {
		t.Error("the user's eth wallet was lost while provisioning the solana one")
	}

	// The create has to go to this user's own wallets collection and carry our signer. Without
	// the signer the wallet exists and the enclave can never sign with it.
	if want := "/v1/users/" + walletTestPrivyID + "/wallets"; state.createPath != want {
		t.Errorf("create path = %q, want %q", state.createPath, want)
	}
	signers := state.createBody.PrivyWalletCreateRequestWallets[0].AdditionalSigners
	if len(signers) != 1 || signers[0].SignerID != "test-signer-id" {
		t.Errorf("create additional_signers = %+v, want the delegated actions quorum", signers)
	}

	// The create answers with the whole user. Folding all of it back in would leave the record
	// with two of every account that has no id to be matched on.
	if got := emailCount(user); got != 1 {
		t.Errorf("email accounts = %d, want 1 — the create response was merged wholesale", got)
	}

	if _, httpErr := cli.GetUser(walletTestPrivyID); httpErr != nil {
		t.Fatalf("second GetUser() error = %+v", httpErr)
	}
	if got := atomic.LoadInt64(&state.createCount); got != 1 {
		t.Errorf("solana creates = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&state.getCount); got != 1 {
		t.Errorf("user fetches = %d, want 1 (the second read must hit the cache)", got)
	}
	if got := cli.userCache.Get(walletTestPrivyID).TTL(); got != userCacheTTL {
		t.Errorf("record TTL = %v, want the full %v once the wallet exists", got, userCacheTTL)
	}
}

// The property the whole design leans on. Every signature on every chain begins by reading the
// user, so a solana create that fails must not be able to fail that read — it would take eth
// signing down for a wallet the request never touched.
func TestGetUser_SurvivesAFailedSolanaCreate(t *testing.T) {
	state := &solServer{
		accounts:     []data.LinkedAccount{walletZeroAccount()},
		createStatus: http.StatusInternalServerError,
	}
	cli := newSolClient(t, state)

	user, httpErr := cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() error = %+v, want the user despite the failed solana create", httpErr)
	}
	if user.GetUsersEthDelegatedWallet() == nil {
		t.Error("user came back without their eth wallet")
	}
	if user.GetUsersSolDelegatedWallet() != nil {
		t.Error("user reports a solana wallet that was never created")
	}

	// The eth path is unaffected in fact, not only in the absence of an error.
	if _, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, walletZeroAddr); httpErr != nil {
		t.Errorf("eth wallet did not resolve after a failed solana create: %+v", httpErr)
	}

	// Swallowing the failure is only acceptable if it is retried. The record is cached, so the
	// retry is its expiry — which has to come soon, not at the full TTL.
	item := cli.userCache.Get(walletTestPrivyID)
	if item == nil {
		t.Fatal("the record was not cached, so every signature would repeat the failing create")
	}
	if got := item.TTL(); got != solWalletRetryTTL {
		t.Errorf("record TTL = %v, want %v so the create is retried soon", got, solWalletRetryTTL)
	}

	// Privy recovers and the short-lived record expires.
	state.set(func(s *solServer) { s.createStatus = 0 })
	cli.userCache.Delete(walletTestPrivyID)

	user, httpErr = cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() after recovery error = %+v", httpErr)
	}
	if user.GetUsersSolDelegatedWallet() == nil {
		t.Error("the solana create was not retried once the record expired")
	}
	if got := atomic.LoadInt64(&state.createCount); got != 2 {
		t.Errorf("solana creates = %d, want 2 (one failed, one retried)", got)
	}
	if got := cli.userCache.Get(walletTestPrivyID).TTL(); got != userCacheTTL {
		t.Errorf("record TTL = %v, want the full %v once the wallet exists", got, userCacheTTL)
	}
}

// A user whose embedded solana wallet was made without our signer cannot be helped from here:
// the create endpoint is a no-op for a chain type they already hold. Asking anyway would be a
// wasted call on every read, for as long as the user stays that way.
func TestGetUser_DoesNotCreateOverAnUndelegatedSolanaWallet(t *testing.T) {
	undelegated := solWalletAccount()
	undelegated.Delegated = false

	state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), undelegated}}
	cli := newSolClient(t, state)

	user, httpErr := cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}
	if user.GetUsersSolDelegatedWallet() != nil {
		t.Error("an undelegated solana wallet was reported as delegated")
	}
	if got := atomic.LoadInt64(&state.createCount); got != 0 {
		t.Errorf("solana creates = %d, want 0 for a user who already holds an embedded solana wallet", got)
	}

	// Nothing is owed, so there is nothing to retry and no reason to expire the record early.
	if got := cli.userCache.Get(walletTestPrivyID).TTL(); got != userCacheTTL {
		t.Errorf("record TTL = %v, want the full %v", got, userCacheTTL)
	}
}

// A wallet the user linked from outside — Phantom, say — is also a solana `wallet` on their
// record, but Privy does not hold its key. It must not be mistaken for the embedded wallet, or
// these users would never be given one the enclave can sign with.
func TestGetUser_CreatesAnEmbeddedSolanaWalletBesideALinkedExternalOne(t *testing.T) {
	external := data.LinkedAccount{
		Type: "wallet", Address: solOtherAddr, ChainType: "solana",
		WalletClientType: "phantom", ConnectorType: "solana_adapter",
	}

	state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), external}}
	cli := newSolClient(t, state)

	user, httpErr := cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}
	if got := atomic.LoadInt64(&state.createCount); got != 1 {
		t.Errorf("solana creates = %d, want 1", got)
	}

	wallet := user.GetUsersSolDelegatedWallet()
	if wallet == nil || wallet.Address != solWalletAddr {
		t.Errorf("delegated solana wallet = %+v, want the embedded one at %s", wallet, solWalletAddr)
	}
}

// Delegation is asserted rather than assumed, as it is for the eth wallet — but a wallet that
// comes back without it is still not allowed to fail the read.
func TestGetUser_ASolanaWalletThatComesBackUndelegatedDoesNotFailTheRead(t *testing.T) {
	state := &solServer{
		accounts:          []data.LinkedAccount{walletZeroAccount()},
		createUndelegated: true,
	}
	cli := newSolClient(t, state)

	user, httpErr := cli.GetUser(walletTestPrivyID)
	if httpErr != nil {
		t.Fatalf("GetUser() error = %+v", httpErr)
	}
	if user.GetUsersSolDelegatedWallet() != nil {
		t.Error("a wallet created without our signer was reported as delegated")
	}

	// And it is not signable: the address exists, but not as a wallet Axal may sign with.
	if _, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, solWalletAddr); httpErr == nil {
		t.Error("an undelegated solana wallet resolved for signing")
	}
}

// The whole Axal route, end to end against Privy's wire format: the wallet is resolved to its
// Privy id, and the body that reaches the RPC is exactly the one Privy documents.
func TestAxalSolSignTransaction_SignsWithTheNamedWallet(t *testing.T) {
	state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}}
	cli := newSolClient(t, state)

	req := data.NewAxalSolSignTransactionRequest(solTestTx, walletTestPrivyID, solWalletAddr)

	resp, httpErr := cli.AxalSolSignTransaction(req, solHMAC(solTestSecret, solTestTx, solWalletAddr, walletTestPrivyID))
	if httpErr != nil {
		t.Fatalf("AxalSolSignTransaction() error = %+v", httpErr)
	}

	if resp.Method != "signTransaction" || resp.Data.SignedTransaction != solSignedTx || resp.Data.Encoding != "base64" {
		t.Errorf("response = %+v, want the signed transaction Privy returned", resp)
	}

	// The request is addressed to the solana wallet's Privy id, not the user's eth wallet.
	if want := "/v1/wallets/wsol0/rpc"; state.rpcPath != want {
		t.Errorf("rpc path = %q, want %q", state.rpcPath, want)
	}

	// Exactly Privy's body. The wallet address and the Privy id are the enclave's own routing
	// and must not leak into it: the authorization signature covers this body, so a stray
	// field is a signature Privy cannot reproduce.
	wantBody := `{"method":"signTransaction","params":{"transaction":"` + solTestTx + `","encoding":"base64"}}`
	if state.rpcBody != wantBody {
		t.Errorf("rpc body = %s, want %s", state.rpcBody, wantBody)
	}
	if state.rpcAuthSig == "" {
		t.Error("the rpc request carried no privy-authorization-signature, so Privy would refuse it")
	}

	// Wallet on the record, so nothing but the signature itself is asked of Privy.
	if got := atomic.LoadInt64(&state.listCount); got != 0 {
		t.Errorf("wallet lookups = %d, want 0 for a wallet already on the record", got)
	}
}

// The HMAC has to cover everything that decides what is signed and by whom. Each case changes
// one of those under a signature computed for the original and must be refused before Privy
// is asked anything at all.
func TestAxalSolSignTransaction_RejectsARequestTheHMACDoesNotCover(t *testing.T) {
	otherTx := base64.StdEncoding.EncodeToString([]byte("a different transaction"))

	// The eth route's preimage shape, for a caller who assumed the two routes shared one.
	ethStyle := func() string {
		mac := hmac.New(sha256.New, []byte(solTestSecret))
		mac.Write([]byte(solTestTx + ":" + walletTestPrivyID + ":" + strings.ToLower(solWalletAddr)))
		return hex.EncodeToString(mac.Sum(nil))
	}()

	for name, signature := range map[string]string{
		"wrong secret":              solHMAC("another-secret", solTestTx, solWalletAddr, walletTestPrivyID),
		"a different transaction":   solHMAC(solTestSecret, otherTx, solWalletAddr, walletTestPrivyID),
		"a different wallet":        solHMAC(solTestSecret, solTestTx, solOtherAddr, walletTestPrivyID),
		"a different user":          solHMAC(solTestSecret, solTestTx, solWalletAddr, "did:privy:cm00000000000000000002"),
		"a lower cased wallet":      solHMAC(solTestSecret, solTestTx, strings.ToLower(solWalletAddr), walletTestPrivyID),
		"the eth preimage":          ethStyle,
		"not a signature":           "deadbeef",
		"an empty signature":        "",
		"the preimage, not its mac": "solana:signTransaction:base64:" + solWalletAddr,
	} {
		t.Run(name, func(t *testing.T) {
			state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}}
			cli := newSolClient(t, state)

			req := data.NewAxalSolSignTransactionRequest(solTestTx, walletTestPrivyID, solWalletAddr)

			resp, httpErr := cli.AxalSolSignTransaction(req, signature)
			if httpErr == nil {
				t.Fatalf("AxalSolSignTransaction() returned %+v, want a refusal", resp)
			}
			if httpErr.Code != http.StatusUnauthorized {
				t.Errorf("Code = %d, want 401", httpErr.Code)
			}
			if got := atomic.LoadInt64(&state.rpcCount); got != 0 {
				t.Errorf("signing requests = %d, want 0", got)
			}
			if got := atomic.LoadInt64(&state.getCount); got != 0 {
				t.Errorf("user fetches = %d, want 0: an unauthenticated request must not reach Privy", got)
			}
		})
	}
}

// The user route: the wallet is resolved against the JWT's user, with no user named in the body.
func TestUserSolSignTransaction_SignsForTheJWTsUser(t *testing.T) {
	state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}}
	cli := newSolClient(t, state)

	req := data.NewUserSolSignTransactionRequest(solTestTx, solWalletAddr)

	resp, httpErr := cli.UserSolSignTransaction(req, cli.jwtFor(t, walletTestPrivyID))
	if httpErr != nil {
		t.Fatalf("UserSolSignTransaction() error = %+v", httpErr)
	}
	if resp.Data.SignedTransaction != solSignedTx {
		t.Errorf("signed transaction = %q, want %q", resp.Data.SignedTransaction, solSignedTx)
	}
	if want := "/v1/wallets/wsol0/rpc"; state.rpcPath != want {
		t.Errorf("rpc path = %q, want %q", state.rpcPath, want)
	}
}

func TestUserSolSignTransaction_RejectsAnInvalidJWT(t *testing.T) {
	state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}}
	cli := newSolClient(t, state)

	// A well-formed token signed by a key the enclave does not trust.
	stranger := newSolClient(t, &solServer{})

	for name, token := range map[string]string{
		"not a jwt":             "not-a-jwt",
		"signed by another key": stranger.jwtFor(t, walletTestPrivyID),
	} {
		t.Run(name, func(t *testing.T) {
			req := data.NewUserSolSignTransactionRequest(solTestTx, solWalletAddr)

			resp, httpErr := cli.UserSolSignTransaction(req, token)
			if httpErr == nil {
				t.Fatalf("UserSolSignTransaction() returned %+v, want a refusal", resp)
			}
			if httpErr.Code != http.StatusUnauthorized {
				t.Errorf("Code = %d, want 401", httpErr.Code)
			}
			if got := atomic.LoadInt64(&state.rpcCount); got != 0 {
				t.Errorf("signing requests = %d, want 0", got)
			}
		})
	}
}

// An authenticated user can put any address in the body. One that is not theirs is refused,
// with the solana wording rather than the eth route's.
func TestSolSignTransaction_RefusesAWalletTheUserDoesNotHold(t *testing.T) {
	state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}}
	cli := newSolClient(t, state)

	req := data.NewUserSolSignTransactionRequest(solTestTx, solOtherAddr)

	resp, httpErr := cli.UserSolSignTransaction(req, cli.jwtFor(t, walletTestPrivyID))
	if httpErr == nil {
		t.Fatalf("UserSolSignTransaction() returned %+v for an address the user does not hold", resp)
	}
	if httpErr.Code != http.StatusBadRequest {
		t.Errorf("Code = %d, want 400", httpErr.Code)
	}
	if want := "requested wallet is not a delegated solana wallet for this user"; httpErr.Message.Message != want {
		t.Errorf("Message = %q, want %q", httpErr.Message.Message, want)
	}
	if got := atomic.LoadInt64(&state.rpcCount); got != 0 {
		t.Errorf("signing requests = %d, want 0", got)
	}
}

// Privy attributing the wallet to someone else is the ownership check failing, and it has to
// hold even though the wallet exists and carries our signer.
func TestResolveDelegatedSolWallet_RefusesAWalletPrivyDoesNotAttributeToTheUser(t *testing.T) {
	state := &solServer{
		accounts:    []data.LinkedAccount{walletZeroAccount()},
		wallet:      solWalletObject(),
		walletOwner: "did:privy:cm00000000000000000002",
	}
	// Give the user a solana wallet of their own at another address, so the read provisions
	// nothing and the only question left is whose wallet solWalletAddr is.
	own := solWalletAccount()
	own.WalletID, own.Address = "wsol-own", solOtherAddr
	state.accounts = append(state.accounts, own)

	cli := newSolClient(t, state)

	account, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, solWalletAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedSolWallet() returned another user's wallet %+v, want a refusal", account)
	}
	if httpErr.Code != http.StatusBadRequest {
		t.Errorf("Code = %d, want 400", httpErr.Code)
	}
}

// Base58 is case sensitive: an address that differs only in case names a different key. The
// mock's list filter ignores case, so what refuses the wallet here is the enclave's own
// comparison — which is the one that must not fold case the way the eth one does.
func TestResolveDelegatedSolWallet_AddressesAreCaseSensitive(t *testing.T) {
	undelegated := solWalletAccount()
	undelegated.Delegated = false

	for name, accounts := range map[string][]data.LinkedAccount{
		"wallet on the record":     {walletZeroAccount(), solWalletAccount()},
		"wallet resolved at Privy": {walletZeroAccount(), undelegated},
	} {
		t.Run(name, func(t *testing.T) {
			state := &solServer{accounts: accounts, wallet: solWalletObject()}
			cli := newSolClient(t, state)

			account, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, strings.ToLower(solWalletAddr))
			if httpErr == nil {
				t.Fatalf("resolveDelegatedSolWallet() resolved %+v for an address that differs in case", account)
			}

			// The exact address still resolves, so the refusal above is about case and nothing else.
			if _, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, solWalletAddr); httpErr != nil {
				t.Errorf("the exact address did not resolve: %+v", httpErr)
			}
		})
	}
}

// Each signing route speaks one chain, fixed by the route. Our quorum is attached to the
// user's wallets on both, so without the chain check a solana transaction could be sent to an
// eth key and an eth hash to a solana one.
func TestResolveDelegatedWallet_TheRouteFixesTheChain(t *testing.T) {
	ethObject := &data.PrivyWallet{
		ID: "w0", Address: walletZeroAddr, ChainType: "ethereum",
		AdditionalSigners: []*data.AdditionalSigner{{SignerID: "test-signer-id"}},
	}

	t.Run("an eth wallet is refused on the solana route", func(t *testing.T) {
		state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}, wallet: ethObject}
		cli := newSolClient(t, state)

		account, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, walletZeroAddr)
		if httpErr == nil {
			t.Fatalf("resolveDelegatedSolWallet() returned eth wallet %+v", account)
		}
		if httpErr.Code != http.StatusBadRequest {
			t.Errorf("Code = %d, want 400", httpErr.Code)
		}
	})

	t.Run("a solana wallet is refused on the eth route", func(t *testing.T) {
		state := &solServer{accounts: []data.LinkedAccount{walletZeroAccount(), solWalletAccount()}, wallet: solWalletObject()}
		cli := newSolClient(t, state)

		account, httpErr := cli.resolveDelegatedWallet(walletTestPrivyID, solWalletAddr)
		if httpErr == nil {
			t.Fatalf("resolveDelegatedWallet() returned solana wallet %+v", account)
		}

		// The eth wording is part of the documented API and must not have changed.
		if want := "requested wallet is not a delegated eth wallet for this user"; httpErr.Message.Message != want {
			t.Errorf("Message = %q, want %q", httpErr.Message.Message, want)
		}
	})
}

// A user who delegates their solana wallet from their own client becomes signable at once,
// even while the cached record still calls the wallet undelegated. The wallet object is where
// the attached signer shows, so that is what is asked.
func TestResolveDelegatedSolWallet_SeesADelegationTheRecordPredates(t *testing.T) {
	undelegated := solWalletAccount()
	undelegated.Delegated = false

	state := &solServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), undelegated},
		wallet:   solWalletObject(),
	}
	cli := newSolClient(t, state)

	account, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, solWalletAddr)
	if httpErr != nil {
		t.Fatalf("resolveDelegatedSolWallet() error = %+v", httpErr)
	}
	if account.WalletID != "wsol0" {
		t.Errorf("WalletID = %q, want wsol0", account.WalletID)
	}

	// Signing is the hot path: the answer is folded into the cached record, so the next
	// signature does not ask again.
	lookups := atomic.LoadInt64(&state.listCount)
	if _, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, solWalletAddr); httpErr != nil {
		t.Fatalf("second resolveDelegatedSolWallet() error = %+v", httpErr)
	}
	if got := atomic.LoadInt64(&state.listCount); got != lookups {
		t.Errorf("wallet lookups = %d, want %d: the resolved wallet was not cached", got, lookups)
	}
}

// The other half of that: a wallet the record calls undelegated and whose signers do not
// include our quorum stays unsignable.
func TestResolveDelegatedSolWallet_RefusesAWalletWithoutAxalsSigner(t *testing.T) {
	undelegated := solWalletAccount()
	undelegated.Delegated = false

	unsignable := solWalletObject()
	unsignable.AdditionalSigners = nil

	state := &solServer{
		accounts: []data.LinkedAccount{walletZeroAccount(), undelegated},
		wallet:   unsignable,
	}
	cli := newSolClient(t, state)

	account, httpErr := cli.resolveDelegatedSolWallet(walletTestPrivyID, solWalletAddr)
	if httpErr == nil {
		t.Fatalf("resolveDelegatedSolWallet() returned unsignable wallet %+v, want a refusal", account)
	}
}

// A 200 from Privy that carries no transaction is not a signature, and must not be handed to
// a caller as one.
func TestSolSignTransaction_RejectsAResponseWithoutASignedTransaction(t *testing.T) {
	state := &solServer{
		accounts:    []data.LinkedAccount{walletZeroAccount(), solWalletAccount()},
		rpcResponse: `{"method":"signTransaction","data":{"encoding":"base64"}}`,
	}
	cli := newSolClient(t, state)

	req := data.NewAxalSolSignTransactionRequest(solTestTx, walletTestPrivyID, solWalletAddr)

	resp, httpErr := cli.AxalSolSignTransaction(req, solHMAC(solTestSecret, solTestTx, solWalletAddr, walletTestPrivyID))
	if httpErr == nil {
		t.Fatalf("AxalSolSignTransaction() returned %+v for a response with no signed transaction", resp)
	}
	if httpErr.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", httpErr.Code)
	}
}

// Privy refusing to sign — a policy violation, a wallet that is not a signer of the
// transaction — is passed through with Privy's status and message, as on the eth routes.
func TestSolSignTransaction_PassesAPrivyRefusalThrough(t *testing.T) {
	state := &solServer{
		accounts:  []data.LinkedAccount{walletZeroAccount(), solWalletAccount()},
		rpcStatus: http.StatusBadRequest,
	}
	cli := newSolClient(t, state)

	req := data.NewAxalSolSignTransactionRequest(solTestTx, walletTestPrivyID, solWalletAddr)

	_, httpErr := cli.AxalSolSignTransaction(req, solHMAC(solTestSecret, solTestTx, solWalletAddr, walletTestPrivyID))
	if httpErr == nil {
		t.Fatal("AxalSolSignTransaction() succeeded although Privy refused to sign")
	}
	if httpErr.Code != http.StatusBadRequest || httpErr.Message.Message != "privy refused to sign" {
		t.Errorf("error = %d %q, want Privy's own 400 and message", httpErr.Code, httpErr.Message.Message)
	}
}
