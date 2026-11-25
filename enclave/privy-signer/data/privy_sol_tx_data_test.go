package data

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testSolWallet      = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
	testSolOtherWallet = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T"
	testSolPrivyID     = "did:privy:cm00000000000000000001"
)

var testSolTx = base64.StdEncoding.EncodeToString([]byte("a serialized solana transaction"))

func validAxalSolRequest() AxalSolSignTransactionRequest {
	return *NewAxalSolSignTransactionRequest(testSolTx, testSolPrivyID, testSolWallet)
}

func TestSolSignTransactionRequestsValidate(t *testing.T) {
	user := NewUserSolSignTransactionRequest(testSolTx, testSolWallet)
	if err := user.ValidateTxRequest(); err != nil {
		t.Errorf("user request: expected valid, got %v", err)
	}

	axal := validAxalSolRequest()
	if err := axal.ValidateTxRequest(); err != nil {
		t.Errorf("axal request: expected valid, got %v", err)
	}
}

// The body as a caller writes it, so the field names on the wire are pinned by a test and
// not only by the struct tags that define them.
func TestSolSignTransactionRequestDecodesTheDocumentedBody(t *testing.T) {
	body := `{
		"privy_id": "` + testSolPrivyID + `",
		"method": "signTransaction",
		"params": { "transaction": "` + testSolTx + `", "encoding": "base64" },
		"wallet_address": "` + testSolWallet + `"
	}`

	var axal AxalSolSignTransactionRequest
	if err := json.Unmarshal([]byte(body), &axal); err != nil {
		t.Fatalf("axal request did not decode: %v", err)
	}
	if err := axal.ValidateTxRequest(); err != nil {
		t.Errorf("axal request: expected valid, got %v", err)
	}
	if axal.PrivyID != testSolPrivyID || axal.WalletAddress != testSolWallet || axal.Params.Transaction != testSolTx {
		t.Errorf("axal request decoded as %+v", axal)
	}

	// The user route takes the same body without the user in it.
	var user UserSolSignTransactionRequest
	if err := json.Unmarshal([]byte(body), &user); err != nil {
		t.Fatalf("user request did not decode: %v", err)
	}
	if err := user.ValidateTxRequest(); err != nil {
		t.Errorf("user request: expected valid, got %v", err)
	}
}

func TestSolSignTransactionRequestRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AxalSolSignTransactionRequest)
	}{
		{"missing method", func(req *AxalSolSignTransactionRequest) { req.Method = "" }},
		// The method that also broadcasts. This route signs and returns; it must not be
		// reachable by asking for more.
		{"sign and send", func(req *AxalSolSignTransactionRequest) { req.Method = "signAndSendTransaction" }},
		{"an eth method", func(req *AxalSolSignTransactionRequest) { req.Method = "secp256k1_sign" }},
		{"missing encoding", func(req *AxalSolSignTransactionRequest) { req.Params.Encoding = "" }},
		{"hex encoding", func(req *AxalSolSignTransactionRequest) { req.Params.Encoding = "hex" }},
		{"empty transaction", func(req *AxalSolSignTransactionRequest) { req.Params.Transaction = "" }},
		{"transaction is not base64", func(req *AxalSolSignTransactionRequest) { req.Params.Transaction = "not base64!" }},
		{"transaction is base58", func(req *AxalSolSignTransactionRequest) { req.Params.Transaction = testSolWallet + "-_" }},
		{"oversized transaction", func(req *AxalSolSignTransactionRequest) {
			req.Params.Transaction = base64.StdEncoding.EncodeToString(make([]byte, maxSolTransactionBytes+1))
		}},
		{"missing privy id", func(req *AxalSolSignTransactionRequest) { req.PrivyID = "" }},
		{"missing wallet", func(req *AxalSolSignTransactionRequest) { req.WalletAddress = "" }},
		{"an eth wallet", func(req *AxalSolSignTransactionRequest) {
			req.WalletAddress = "0xaaaa000000000000000000000000000000000001"
		}},
		// 0, O, I and l are not in the base58 alphabet.
		{"wallet outside the base58 alphabet", func(req *AxalSolSignTransactionRequest) {
			req.WalletAddress = "0WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
		}},
		{"wallet too short", func(req *AxalSolSignTransactionRequest) { req.WalletAddress = testSolWallet[:31] }},
		{"wallet too long", func(req *AxalSolSignTransactionRequest) { req.WalletAddress = testSolWallet + "A" }},
		{"wallet with a path in it", func(req *AxalSolSignTransactionRequest) {
			req.WalletAddress = testSolWallet[:40] + "/rpc"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validAxalSolRequest()
			tt.mutate(&req)

			if err := req.ValidateTxRequest(); err == nil {
				t.Errorf("expected the request to be rejected: %+v", req)
			}
		})
	}
}

// A transaction at the bound is accepted, so the bound is the one the constant names.
func TestSolSignTransactionRequestAcceptsATransactionAtTheBound(t *testing.T) {
	req := validAxalSolRequest()
	req.Params.Transaction = base64.StdEncoding.EncodeToString(make([]byte, maxSolTransactionBytes))

	if err := req.ValidateTxRequest(); err != nil {
		t.Errorf("expected a %d byte transaction to be accepted, got %v", maxSolTransactionBytes, err)
	}
}

// What reaches Privy is Privy's body and nothing else. The wallet address and the Privy id
// are the enclave's own routing; the authorization signature covers this body, so a field
// that leaked into it would be a signature Privy cannot reproduce.
func TestSolSignTransactionRequestSendsPrivyOnlyItsOwnBody(t *testing.T) {
	want := `{"method":"signTransaction","params":{"transaction":"` + testSolTx + `","encoding":"base64"}}`

	axal := validAxalSolRequest()
	got, err := json.Marshal(axal.GetPrivySignData())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("axal privy body = %s, want %s", got, want)
	}

	user := NewUserSolSignTransactionRequest(testSolTx, testSolWallet)
	got, err = json.Marshal(user.GetPrivySignData())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("user privy body = %s, want %s", got, want)
	}
}

// The preimage is a contract with the caller, so it is pinned literally.
func TestAxalSolSignTransactionAuthPayload(t *testing.T) {
	req := validAxalSolRequest()

	digest := sha256.Sum256([]byte(testSolTx))
	want := "solana:signTransaction:base64:" + testSolWallet + ":" + hex.EncodeToString(digest[:]) + ":" + testSolPrivyID

	if got := req.AuthPayload(); got != want {
		t.Errorf("AuthPayload() = %q, want %q", got, want)
	}
}

// Everything that decides what is signed, and by whom, has to move the preimage.
func TestAxalSolSignTransactionAuthPayloadBindsEveryInput(t *testing.T) {
	original := validAxalSolRequest()
	base := original.AuthPayload()

	for name, mutate := range map[string]func(*AxalSolSignTransactionRequest){
		"transaction": func(req *AxalSolSignTransactionRequest) {
			req.Params.Transaction = base64.StdEncoding.EncodeToString([]byte("a different transaction"))
		},
		"wallet":   func(req *AxalSolSignTransactionRequest) { req.WalletAddress = testSolOtherWallet },
		"user":     func(req *AxalSolSignTransactionRequest) { req.PrivyID = "did:privy:cm00000000000000000002" },
		"method":   func(req *AxalSolSignTransactionRequest) { req.Method = "signAndSendTransaction" },
		"encoding": func(req *AxalSolSignTransactionRequest) { req.Params.Encoding = "hex" },
		// The eth preimages lower case the wallet. Here that would make two keys share one.
		"wallet casing": func(req *AxalSolSignTransactionRequest) {
			req.WalletAddress = strings.ToLower(req.WalletAddress)
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := validAxalSolRequest()
			mutate(&req)

			if req.AuthPayload() == base {
				t.Errorf("changing the %s left the preimage unchanged", name)
			}
		})
	}
}

// The transaction is hashed into the preimage, not written into it.
func TestAxalSolSignTransactionAuthPayloadDoesNotCarryTheTransaction(t *testing.T) {
	req := validAxalSolRequest()

	if strings.Contains(req.AuthPayload(), testSolTx) {
		t.Error("the preimage carries the raw transaction")
	}
}

// Privy's documented response, decoded and re-encoded: the caller reads the same field names
// Privy wrote.
func TestSolSignTransactionResponseRoundTrips(t *testing.T) {
	privy := `{"method":"signTransaction","data":{"signed_transaction":"c2lnbmVk","encoding":"base64"}}`

	var resp SolSignTransactionResponse
	if err := json.Unmarshal([]byte(privy), &resp); err != nil {
		t.Fatalf("response did not decode: %v", err)
	}
	if resp.Method != "signTransaction" || resp.Data.SignedTransaction != "c2lnbmVk" || resp.Data.Encoding != "base64" {
		t.Errorf("response decoded as %+v", resp)
	}

	got, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != privy {
		t.Errorf("response = %s, want %s", got, privy)
	}
}

// solUser holds wallets on both chains plus the cases the solana lookups have to tell apart.
func solUser(solAccounts ...LinkedAccount) *PrivyUser {
	accounts := []LinkedAccount{
		{Type: "email", Address: "user@example.com"},
		{WalletID: "w0", Type: "wallet", Address: walletZero, ChainType: "ethereum", Delegated: true},
	}

	return &PrivyUser{PrivyID: testSolPrivyID, LinkedAccounts: append(accounts, solAccounts...)}
}

func embeddedSolWallet(delegated bool) LinkedAccount {
	return LinkedAccount{
		WalletID: "wsol0", Type: "wallet", Address: testSolWallet, ChainType: "solana",
		Delegated: delegated, WalletClientType: "privy", ConnectorType: "embedded",
	}
}

func TestGetSolDelegatedWalletByAddress(t *testing.T) {
	user := solUser(embeddedSolWallet(true))

	got := user.GetSolDelegatedWalletByAddress(testSolWallet)
	if got == nil || got.WalletID != "wsol0" {
		t.Fatalf("GetSolDelegatedWalletByAddress() = %+v, want wallet wsol0", got)
	}

	// Every one of these has to come back nil, so the caller refuses rather than signing with
	// a wallet that was not the one named.
	for name, address := range map[string]string{
		"empty":           "",
		"another address": testSolOtherWallet,
		// Base58 is case sensitive: these name different keys, not the same wallet.
		"lower cased": strings.ToLower(testSolWallet),
		"upper cased": strings.ToUpper(testSolWallet),
		// The user's eth wallet is delegated too, but it is not a solana wallet.
		"the eth wallet": walletZero,
		// LinkedAccount.Address also carries email addresses.
		"the email": "user@example.com",
	} {
		t.Run(name, func(t *testing.T) {
			if got := user.GetSolDelegatedWalletByAddress(address); got != nil {
				t.Errorf("GetSolDelegatedWalletByAddress(%q) = %+v, want nil", address, got)
			}
		})
	}

	// And the solana wallet is not an eth wallet, whatever address is asked for.
	if got := user.GetEthDelegatedWalletByAddress(testSolWallet); got != nil {
		t.Errorf("GetEthDelegatedWalletByAddress() returned the solana wallet %+v", got)
	}
}

func TestGetSolDelegatedWalletByAddress_IgnoresAnUndelegatedWallet(t *testing.T) {
	user := solUser(embeddedSolWallet(false))

	if got := user.GetSolDelegatedWalletByAddress(testSolWallet); got != nil {
		t.Errorf("GetSolDelegatedWalletByAddress() = %+v, want nil for a wallet Axal cannot sign with", got)
	}
}

// Whether a solana wallet is still owed decides whether the enclave asks Privy for one.
func TestNeedsSolWallet(t *testing.T) {
	external := LinkedAccount{
		Type: "wallet", Address: testSolOtherWallet, ChainType: "solana",
		WalletClientType: "phantom", ConnectorType: "solana_adapter",
	}

	for _, tc := range []struct {
		name         string
		user         *PrivyUser
		wantEmbedded bool
		wantNeeds    bool
	}{
		{name: "no solana wallet", user: solUser(), wantEmbedded: false, wantNeeds: true},
		{name: "delegated embedded wallet", user: solUser(embeddedSolWallet(true)), wantEmbedded: true, wantNeeds: false},
		// Nothing to create: the endpoint is a no-op for a chain type the user already holds.
		{name: "undelegated embedded wallet", user: solUser(embeddedSolWallet(false)), wantEmbedded: true, wantNeeds: false},
		// Privy does not hold this key, so it is no substitute for an embedded wallet.
		{name: "only a linked external wallet", user: solUser(external), wantEmbedded: false, wantNeeds: true},
		{name: "external and embedded", user: solUser(external, embeddedSolWallet(true)), wantEmbedded: true, wantNeeds: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.user.HasEmbeddedSolWallet(); got != tc.wantEmbedded {
				t.Errorf("HasEmbeddedSolWallet() = %t, want %t", got, tc.wantEmbedded)
			}
			if got := tc.user.NeedsSolWallet(); got != tc.wantNeeds {
				t.Errorf("NeedsSolWallet() = %t, want %t", got, tc.wantNeeds)
			}
		})
	}
}

func TestSameWalletAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain string
		a, b  string
		want  bool
	}{
		{"eth exact", ChainTypeEthereum, walletZero, walletZero, true},
		{"eth checksummed casing", ChainTypeEthereum, walletZero, "0x" + strings.ToUpper(walletZero[2:]), true},
		{"eth different", ChainTypeEthereum, walletZero, walletOne, false},
		{"solana exact", ChainTypeSolana, testSolWallet, testSolWallet, true},
		{"solana differing in case", ChainTypeSolana, testSolWallet, strings.ToLower(testSolWallet), false},
		{"solana different", ChainTypeSolana, testSolWallet, testSolOtherWallet, false},
		// Two missing addresses are not the same wallet.
		{"both empty", ChainTypeSolana, "", "", false},
		{"one empty", ChainTypeEthereum, walletZero, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SameWalletAddress(tc.chain, tc.a, tc.b); got != tc.want {
				t.Errorf("SameWalletAddress(%s, %q, %q) = %t, want %t", tc.chain, tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// The create body as Privy documents it for this endpoint, with our signer attached.
func TestNewCreateSolWalletRequest(t *testing.T) {
	got, err := json.Marshal(NewCreateSolWalletRequest("signer-quorum-id"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := `{"wallets":[{"chain_type":"solana","additional_signers":[{"signer_id":"signer-quorum-id"}]}]}`
	if string(got) != want {
		t.Errorf("create body = %s, want %s", got, want)
	}

	// The eth request shares the builder and must not have moved.
	got, err = json.Marshal(NewCreateEthWalletRequest("signer-quorum-id"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want = `{"wallets":[{"chain_type":"ethereum","additional_signers":[{"signer_id":"signer-quorum-id"}]}]}`
	if string(got) != want {
		t.Errorf("eth create body = %s, want %s", got, want)
	}
}
