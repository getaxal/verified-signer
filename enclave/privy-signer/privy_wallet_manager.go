package privysigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// walletCreateResult carries both values through the singleflight.Group, which only
// exposes a plain error channel.
type walletCreateResult struct {
	wallet  *data.LinkedAccount
	httpErr *data.HttpError
}

// Provisions an additional delegated eth wallet for a user and returns it.
//
// Asking twice for the same purpose returns the same wallet rather than minting a second
// one. That matters more than it looks: a duplicate wallet is not a failed request that
// can be retried away, it is a second address that may already have received money, with
// no way to tell which one the user's funds went to. Three guards stack up, so no single
// one has to be perfect:
//
//  1. a singleflight group keyed on the external id collapses concurrent callers in this
//     enclave into one create;
//  2. the create is skipped entirely when the user already holds the wallet;
//  3. Privy is sent a deterministic idempotency key and a unique external id, which
//     covers retries this process never sees — a caller that gave up and redialled, or a
//     second enclave instance.
//
// Guard 3 is the only one that holds across instances, so it is the one to verify against
// Privy rather than assume.
func (cli *PrivyClient) CreateUserWallet(privyId string, purpose string) (*data.LinkedAccount, *data.HttpError) {
	externalID, err := data.WalletExternalID(privyId, purpose)
	if err != nil {
		log.Errorf("Create wallet API error: %v", err)
		return nil, &data.HttpError{
			Code:    http.StatusBadRequest,
			Message: data.Message{Message: "purpose is invalid"},
		}
	}

	res, _, _ := cli.walletCreateGroup.Do(externalID, func() (interface{}, error) {
		wallet, httpErr := cli.createWalletForPurpose(privyId, externalID)
		return walletCreateResult{wallet: wallet, httpErr: httpErr}, nil
	})

	result := res.(walletCreateResult)
	if result.httpErr != nil {
		return nil, result.httpErr
	}

	// Hand each collapsed caller its own copy, matching GetUser's semantics.
	wallet := *result.wallet
	return &wallet, nil
}

// Runs inside the singleflight critical section for one external id.
func (cli *PrivyClient) createWalletForPurpose(privyId string, externalID string) (*data.LinkedAccount, *data.HttpError) {
	// GetUser gives us the current wallet set and, as a side effect, guarantees the user
	// has a wallet at HD index 0 — which Privy requires before it will create a wallet at
	// any higher index.
	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	if existing := user.GetEthDelegatedWalletByExternalID(externalID); existing != nil {
		log.Infof("User %s already has a wallet for external id %s", privyId, externalID)
		return existing, nil
	}

	// The check above can only recognise the wallet if Privy echoes our external id back
	// inside linked_accounts, so it is not enough on its own: when it does not, a user who
	// already holds the wallet looks like one who does not. Asking Privy for the wallet by
	// external id settles it, because external ids are unique per app and addressable
	// directly.
	existing, httpErr := cli.findWalletByExternalID(privyId, externalID)
	if httpErr != nil {
		return nil, httpErr
	}
	if existing != nil {
		return existing, nil
	}

	// Recorded before the create so the new wallet can be told apart from the ones the
	// response may echo back alongside it.
	known := knownWalletIDs(user)

	createResp, httpErr := cli.postCreateWallet(privyId, externalID)
	if httpErr != nil {
		return nil, httpErr
	}

	wallet := selectCreatedWallet(createResp.LinkedAccounts, externalID, known)
	if wallet == nil {
		// Privy answered 200, so a wallet very likely exists even though the response did
		// not name it. Failing here is not the transient failure a caller can retry away:
		// the idempotency key is derived from the external id, so Privy replays this same
		// response for 24 hours and every retry fails identically, while the wallet it
		// created sits uncached and unusable.
		//
		// The user record is the source of truth for what the user holds, so consult it
		// before giving up. The summary logged here says which assumption broke: no
		// accounts at all means the response is not shaped the way we parse it; accounts
		// carrying no external id means Privy did not echo ours; every id already known
		// means this was an idempotent replay of an earlier create.
		log.Warnf("Create wallet: response for user %s did not name the new wallet (response id %q, accounts %s), refetching the user",
			privyId, createResp.ID, summarizeAccounts(createResp.LinkedAccounts))

		return cli.resolveCreatedWallet(privyId, externalID, known)
	}

	if httpErr := cli.assertDelegatedEthWallet(wallet, privyId); httpErr != nil {
		return nil, httpErr
	}

	// Make the cache consistent with Privy before returning, not after.
	//
	// The signing path resolves addresses out of this record, so a caller that provisions a
	// wallet and immediately signs with it must find it there. Evicting instead would work
	// too, but it would leave the very next signature to race a refetch; writing the record
	// back means the wallet is usable the moment this call returns 200.
	cli.cacheUser(privyId, mergedUser(user, createResp.LinkedAccounts))

	return wallet, nil
}

// Identifies a just-created wallet from Privy's user record rather than from the body of
// the create response.
//
// This is the recovery path for a create that returned 200 without a wallet we could pick
// out of the response. Privy has been asked to create the wallet and said yes, so the
// question is no longer whether it exists but what it is, and the user record answers that
// without depending on the create response echoing anything back.
//
// The cached record is dropped first: it was read before the create, so going through it
// would reproduce the very miss that brought us here.
func (cli *PrivyClient) resolveCreatedWallet(privyId string, externalID string, known map[string]bool) (*data.LinkedAccount, *data.HttpError) {
	// Privy knows the wallet by the external id we gave it whether or not it echoed that id
	// back, so this resolves the case the create response could not: an idempotent replay
	// of an earlier create, whose wallet is already in `known` and so indistinguishable
	// from the ones the user held before.
	if wallet, httpErr := cli.findWalletByExternalID(privyId, externalID); httpErr != nil || wallet != nil {
		return wallet, httpErr
	}

	cli.InvalidateUser(privyId)

	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	accounts := make([]*data.LinkedAccount, 0, len(user.LinkedAccounts))
	for i := range user.LinkedAccounts {
		accounts = append(accounts, &user.LinkedAccounts[i])
	}

	wallet := selectCreatedWallet(accounts, externalID, known)
	if wallet == nil {
		log.Errorf("Create wallet API error: created wallet for user %s could not be identified in the response or in the refetched user (accounts %s)",
			privyId, summarizeAccounts(accounts))
		return nil, cli.createInternalServerError()
	}

	if httpErr := cli.assertDelegatedEthWallet(wallet, privyId); httpErr != nil {
		return nil, httpErr
	}

	// Copied out of the refetched record, whose LinkedAccounts slice shares its backing
	// array with the cache entry GetUser just wrote.
	found := *wallet

	// GetUser has already cached this record, so the cache is consistent with what we
	// return and needs no second write.
	return &found, nil
}

// Resolves the user's linked account for the wallet carrying an external id, or nil when
// Privy holds no wallet under it.
//
// Two sources are combined because each is authoritative for a different half of the
// answer. The wallet endpoint knows which wallet the external id belongs to and which
// signers are attached to it; only the user record carries the wallet_index and the
// delegated flag the signing path resolves addresses against. So the external id is turned
// into an address here, and the address into a linked account.
func (cli *PrivyClient) findWalletByExternalID(privyId string, externalID string) (*data.LinkedAccount, *data.HttpError) {
	wallet, httpErr := cli.getWalletByExternalID(externalID)
	if httpErr != nil || wallet == nil {
		return nil, httpErr
	}

	account, httpErr := cli.linkedAccountForAddress(privyId, wallet.Address)
	if httpErr != nil {
		return nil, httpErr
	}

	if account == nil {
		// A wallet exists under our external id but the user does not hold it as a
		// delegated eth wallet, so every Axal-initiated signature for it would be refused.
		// Creating another one is not the answer — external ids are unique per app, so the
		// next create would collide on this same wallet — hence an error rather than a
		// fallthrough. Whether our signer is attached says which side to look at: attached
		// means Privy is not reporting the wallet as delegated on the user; not attached
		// means the create did not apply additional_signers at all.
		log.Errorf("Create wallet API error: wallet %s under external id %s is not a delegated eth wallet on user %s (signer %s attached: %t, chain_type %q)",
			wallet.ID, externalID, privyId, cli.teeConfig.Privy.DelegatedActionsKeyId,
			wallet.HasAdditionalSigner(cli.teeConfig.Privy.DelegatedActionsKeyId), wallet.ChainType)

		return nil, cli.createInternalServerError()
	}

	log.Infof("User %s already has wallet %s for external id %s", privyId, wallet.ID, externalID)

	return account, nil
}

// Fetches the wallet carrying an external id, or nil when Privy holds none.
//
// This is the one duplicate guard that is both authoritative and independent of what Privy
// echoes back in linked_accounts, which is what makes it worth an extra round trip on the
// provisioning path.
func (cli *PrivyClient) getWalletByExternalID(externalID string) (*data.PrivyWallet, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, GET_WALLET_PATH.Build(data.ExternalWalletRef(externalID)))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("failed to create wallet lookup request: %v", err)
		return nil, cli.createInternalServerError()
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("error sending the wallet lookup request: %v", err)
		return nil, cli.createInternalServerError()
	}

	defer res.Body.Close()

	// No wallet under this external id is the expected answer the first time a purpose is
	// provisioned, not a failure.
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if res.StatusCode != http.StatusOK {
		log.Errorf("Wallet lookup API error: privy returned status %d for external id %s", res.StatusCode, externalID)
		return nil, handlePrivyError(res)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading wallet lookup response body: %v", err)
		return nil, cli.createInternalServerError()
	}

	var wallet data.PrivyWallet
	if err := json.Unmarshal(body, &wallet); err != nil {
		log.Errorf("unable to unmarshal wallet lookup response: %v", err)
		return nil, cli.createInternalServerError()
	}

	if wallet.Address == "" {
		log.Errorf("Wallet lookup API error: wallet under external id %s came back without an address", externalID)
		return nil, cli.createInternalServerError()
	}

	return &wallet, nil
}

// Finds the user's delegated eth wallet at an address, refetching the user once when the
// cached record does not carry it.
//
// The refetch is what makes this usable straight after a create: the cached record was read
// before the wallet existed, so a miss against it is expected rather than conclusive. A
// miss against a freshly fetched record is conclusive, and the nil it returns means the
// user genuinely does not hold this wallet as a delegated eth wallet.
func (cli *PrivyClient) linkedAccountForAddress(privyId string, address string) (*data.LinkedAccount, *data.HttpError) {
	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	if account := user.GetEthDelegatedWalletByAddress(address); account != nil {
		return account, nil
	}

	cli.InvalidateUser(privyId)

	user, httpErr = cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	// Copied out of the refetched record, whose LinkedAccounts slice shares its backing
	// array with the cache entry GetUser just wrote. GetUser has also cached that record,
	// so the cache is consistent with whatever is returned here.
	if account := user.GetEthDelegatedWalletByAddress(address); account != nil {
		found := *account
		return &found, nil
	}

	return nil, nil
}

// Asserts delegation rather than trusting the Privy default. A wallet created without our
// signer attached would serve user-initiated signing and fail every Axal-initiated one —
// rebalancing and reward claiming — silently, at a time nobody is watching.
func (cli *PrivyClient) assertDelegatedEthWallet(wallet *data.LinkedAccount, privyId string) *data.HttpError {
	if !wallet.Delegated || wallet.ChainType != "ethereum" {
		log.Errorf("Create wallet API error: wallet created for user %s is not a delegated eth wallet (chain_type %q, delegated %t)",
			privyId, wallet.ChainType, wallet.Delegated)
		return cli.createInternalServerError()
	}

	return nil
}

// The set of wallet ids a user already holds, used to tell a newly created wallet apart
// from the ones a response echoes back alongside it.
func knownWalletIDs(user *data.PrivyUser) map[string]bool {
	known := make(map[string]bool, len(user.LinkedAccounts))
	for _, acc := range user.LinkedAccounts {
		if acc.WalletID != "" {
			known[acc.WalletID] = true
		}
	}

	return known
}

// Renders the identifying fields of a set of linked accounts for a log line.
//
// Deliberately not the raw response body: linked accounts carry the user's email and
// wallet addresses, and neither is needed to work out why a wallet could not be identified.
func summarizeAccounts(accounts []*data.LinkedAccount) string {
	if len(accounts) == 0 {
		return "[]"
	}

	parts := make([]string, 0, len(accounts))
	for _, acc := range accounts {
		if acc == nil {
			parts = append(parts, "<nil>")
			continue
		}

		parts = append(parts, fmt.Sprintf("{id:%q type:%q chain:%q index:%d delegated:%t external_id:%q}",
			acc.WalletID, acc.Type, acc.ChainType, acc.WalletIndex, acc.Delegated, acc.ExternalID))
	}

	return "[" + strings.Join(parts, " ") + "]"
}

// Returns a copy of the user with the create-wallet response folded in.
//
// The copy is not optional. GetUser hands back a shallow copy whose LinkedAccounts slice
// still shares its backing array with the cached entry, so merging in place would reach
// through and mutate the cache underneath other readers.
func mergedUser(user *data.PrivyUser, accounts []*data.LinkedAccount) *data.PrivyUser {
	updated := *user
	updated.LinkedAccounts = append([]data.LinkedAccount(nil), user.LinkedAccounts...)
	mergeLinkedAccounts(&updated, accounts)

	return &updated
}

// Picks the newly created wallet out of a create-wallet response.
//
// Matching on external id is exact and preferred. Privy does not necessarily echo every
// field back, so the fallback is the delegated eth wallet the user did not already hold,
// which is unambiguous because this call creates exactly one.
func selectCreatedWallet(accounts []*data.LinkedAccount, externalID string, known map[string]bool) *data.LinkedAccount {
	for _, acc := range accounts {
		if acc != nil && acc.ExternalID != "" && acc.ExternalID == externalID {
			return acc
		}
	}

	for _, acc := range accounts {
		if acc == nil || known[acc.WalletID] {
			continue
		}
		if acc.Delegated && acc.ChainType == "ethereum" {
			return acc
		}
	}

	return nil
}

// Posts the create-wallet call to Privy, carrying the external id and a deterministic
// idempotency key so a retried request cannot become a second wallet.
func (cli *PrivyClient) postCreateWallet(privyId string, externalID string) (*data.CreateWalletResponse, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, CREATE_WALLET_PATH.Build(privyId))

	walletCreateReq := data.NewCreateEthWalletRequestWithExternalID(cli.teeConfig.Privy.DelegatedActionsKeyId, externalID)

	requestBody, err := json.Marshal(walletCreateReq)
	if err != nil {
		log.Errorf("failed to marshal wallet create request: %v", err)
		return nil, cli.createInternalServerError()
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Errorf("failed to create request: %v", err)
		return nil, cli.createInternalServerError()
	}

	cli.addStandardPrivyHeaders(req)

	// Derived from the external id, so it is the same key every time this wallet is
	// requested. Privy holds idempotency records for 24 hours, which covers the retry
	// window our own guards cannot see.
	req.Header.Add("privy-idempotency-key", "wallet-create:"+externalID)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("error sending the client request: %v", err)
		return nil, cli.createInternalServerError()
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Errorf("Create wallet API error: privy returned status %d", res.StatusCode)
		return nil, handlePrivyError(res)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return nil, cli.createInternalServerError()
	}

	var createWalletResp data.CreateWalletResponse
	if err := json.Unmarshal(body, &createWalletResp); err != nil {
		log.Errorf("unable to unmarshal create wallet response: %v", err)
		return nil, cli.createInternalServerError()
	}

	return &createWalletResp, nil
}
