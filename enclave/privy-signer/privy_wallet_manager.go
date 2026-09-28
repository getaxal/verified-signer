package privysigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// Reported as a wallet's HD index when the wallet is known to have one but the record that
// holds it has not been read yet. Not zero, which is the index of the user's primary wallet.
const unknownWalletIndex = -1

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
// no way to tell which one the user's funds went to. Four guards stack up, so no single
// one has to be perfect:
//
//  1. a singleflight group keyed on the external id collapses concurrent callers in this
//     enclave into one create;
//  2. the create is skipped entirely when the user already holds the wallet;
//  3. the wallet is looked up by external id directly, which answers whether one exists
//     regardless of what the user's linked accounts show;
//  4. Privy is sent a deterministic idempotency key, and the external id is unique per app,
//     so a duplicate create collides server side rather than quietly producing a second
//     funded address.
//
// Guards 3 and 4 are the ones that hold across instances, and guard 3 is the only one that
// does not depend on Privy echoing our external id back inside linked_accounts.
func (cli *PrivyClient) CreateUserWallet(privyId string, purpose string) (*data.LinkedAccount, *data.HttpError) {
	externalID, err := data.WalletExternalID(privyId, purpose)
	if err != nil {
		log.Errorf("Create wallet API error: purpose %q is not usable for user %s: %v", purpose, privyId, err)
		return nil, &data.HttpError{
			Code:    http.StatusBadRequest,
			Message: data.Message{Message: "purpose is invalid"},
		}
	}

	// Provisioning is rare and each call moves money-bearing state, so it is logged step by
	// step. The cost of a few lines per call is nothing next to reconstructing, after the
	// fact, which of Privy's answers the enclave acted on.
	log.Infof("Wallet provisioning: user %s, purpose %q, external id %s", privyId, purpose, externalID)

	res, _, shared := cli.walletCreateGroup.Do(externalID, func() (interface{}, error) {
		wallet, httpErr := cli.createWalletForPurpose(privyId, externalID)
		return walletCreateResult{wallet: wallet, httpErr: httpErr}, nil
	})

	// Says whether this answer was produced for this caller or collapsed onto another one
	// already in flight, which is otherwise invisible and is the first thing to know when two
	// callers disagree about what they got.
	if shared {
		log.Infof("Wallet provisioning: external id %s was served by a create shared across concurrent callers", externalID)
	}

	result := res.(walletCreateResult)
	if result.httpErr != nil {
		log.Errorf("Wallet provisioning failed: user %s, purpose %q, external id %s, responding %d %s",
			privyId, purpose, externalID, result.httpErr.Code, result.httpErr.Message.Message)
		return nil, result.httpErr
	}

	log.Infof("Wallet provisioning succeeded: user %s, purpose %q, wallet %s at index %d",
		privyId, purpose, result.wallet.WalletID, result.wallet.WalletIndex)

	// Hand each collapsed caller its own copy, matching GetUser's semantics.
	wallet := *result.wallet
	return &wallet, nil
}

// Runs inside the singleflight critical section for one external id.
func (cli *PrivyClient) createWalletForPurpose(privyId string, externalID string) (*data.LinkedAccount, *data.HttpError) {
	// GetUser gives us the current wallet set and, as a side effect, guarantees the user has
	// a wallet at HD index 0, which is the wallet the rest of the product assumes exists.
	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	if existing := user.GetEthDelegatedWalletByExternalID(externalID); existing != nil {
		log.Infof("Wallet provisioning: user %s already holds wallet %s at index %d for external id %s, returning it",
			privyId, existing.WalletID, existing.WalletIndex, externalID)
		return existing, nil
	}

	log.Infof("Wallet provisioning: external id %s is not on user %s's record (accounts %s), asking Privy directly",
		externalID, privyId, summarizeUserAccounts(user))

	// The check above can only recognise the wallet if Privy echoes our external id back
	// inside linked_accounts, so it is not enough on its own: when it does not, a user who
	// already holds the wallet looks like one who does not. Asking Privy for the wallet by
	// external id settles it, because external ids are unique per app and addressable
	// directly.
	existing, httpErr := cli.findWalletByExternalID(privyId, user, externalID)
	if httpErr != nil {
		return nil, httpErr
	}
	if existing != nil {
		return existing, nil
	}

	log.Infof("Wallet provisioning: no wallet exists under external id %s, creating one for user %s", externalID, privyId)

	wallet, httpErr := cli.postCreateWallet(privyId, externalID)
	if httpErr != nil {
		// A failed create does not mean no wallet. The request may have landed and its
		// response been lost, and Privy caches 4xx and 5xx responses against the idempotency
		// key and replays them for 24 hours — so this error may be a replay of one already
		// recovered from. Reporting failure without looking would strand a wallet that
		// exists, and leave the next call to be answered by the same cached error.
		log.Warnf("Wallet provisioning: create for user %s failed with %d, checking whether a wallet exists under external id %s anyway",
			privyId, httpErr.Code, externalID)

		recovered, lookupErr := cli.findWalletByExternalID(privyId, user, externalID)
		if lookupErr == nil && recovered != nil {
			log.Warnf("Wallet provisioning: create for user %s failed but wallet %s exists under external id %s, returning it",
				privyId, recovered.WalletID, externalID)
			return recovered, nil
		}

		if lookupErr != nil {
			log.Errorf("Wallet provisioning: could not check for a wallet under external id %s after the create failed, reporting the create failure", externalID)
		} else {
			log.Errorf("Wallet provisioning: create for user %s failed and no wallet exists under external id %s", privyId, externalID)
		}

		return nil, httpErr
	}

	account, httpErr := cli.accountForWallet(privyId, user, externalID, wallet)
	if httpErr != nil {
		return nil, httpErr
	}

	// Make the wallet resolvable from the cached record, so a caller that provisions and then
	// immediately signs does not pay a second lookup. The entry is ours rather than Privy's, so
	// it is dropped on the next user refetch — which is harmless, because the address lookup
	// that produced it is also what recovers it.
	cli.cacheUser(privyId, mergedUser(user, []*data.LinkedAccount{account}))

	return account, nil
}

// Turns a Privy wallet into the linked account the rest of the enclave works with, or fails
// if the wallet is not one Axal can sign for on this user's behalf.
//
// The wallet object is the whole source of truth here, deliberately. A wallet created on
// Privy's wallet API is owned by a key quorum and is not listed among the user's linked
// accounts, so the user record cannot confirm it, cannot supply a delegated flag for it, and
// has no HD index to give it. What makes the wallet usable is on the wallet itself: our quorum
// among its signers, and an external id saying it was provisioned for this user.
func (cli *PrivyClient) accountForWallet(privyId string, user *data.PrivyUser, externalID string, wallet *data.PrivyWallet) (*data.LinkedAccount, *data.HttpError) {
	// Ownership, for this path: the external id was derived from the authenticated user, so a
	// wallet carrying it is theirs. Asserted rather than assumed, in case the id we looked up
	// and the id on the wallet ever diverge.
	if !data.ExternalIDBelongsToUser(wallet.ExternalID, privyId) {
		log.Errorf("Create wallet API error: wallet under external id %s does not belong to user %s: %s",
			externalID, privyId, summarizeWallet(wallet))
		return nil, cli.createInternalServerError()
	}

	account := cli.signableAccountForWallet(privyId, wallet)
	if account == nil {
		log.Errorf("Create wallet API error: the wallet under external id %s is not usable for user %s", externalID, privyId)
		return nil, cli.createInternalServerError()
	}

	// Prefer the user's record. A wallet created this way is a real embedded wallet and lands in
	// linked_accounts at the next HD index, which is where its wallet_index and delegated flag
	// come from — the wallet object carries neither.
	//
	// It is preferred, not required. That read is eventually consistent: usually the wallet is
	// there the instant the create returns, but it has been seen to lag past the end of the
	// request that made it. Failing in that window would turn a wallet that exists, is funded
	// and is signable into a 500, which is exactly what used to happen here.
	if fromRecord := cli.userAccountForWallet(privyId, user, wallet.Address); fromRecord != nil {
		log.Infof("Wallet %s (%s) is on user %s's record at index %d",
			wallet.ID, wallet.Address, privyId, fromRecord.WalletIndex)

		// The external id is not in linked_accounts — Privy does not echo it there — so it is
		// carried over from the wallet object. Without it the cached record cannot recognise
		// this wallet on a repeat provisioning call.
		fromRecord.ExternalID = wallet.ExternalID

		return fromRecord, nil
	}

	log.Warnf("Wallet %s (%s) is not yet on user %s's record; returning it with an unknown wallet_index",
		wallet.ID, wallet.Address, privyId)

	return account, nil
}

// Finds a wallet on the user's record by address, or nil when the record does not carry it.
//
// The record already in hand is tried first, and it answers on every repeat call: these wallets
// live in linked_accounts, so a wallet that existed before this request is already in the record
// read at the top of it. Only a wallet created during this request can be missing, because that
// record predates it — so that is the only case that pays a reread.
func (cli *PrivyClient) userAccountForWallet(privyId string, user *data.PrivyUser, address string) *data.LinkedAccount {
	if user != nil {
		if account := user.GetEthDelegatedWalletByAddress(address); account != nil {
			found := *account
			return &found
		}
	}

	// Past the cache deliberately: the entry holds the same pre-create record just checked.
	cli.InvalidateUser(privyId)

	refetched, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		log.Warnf("Could not reread user %s to place wallet %s: %+v", privyId, address, httpErr)
		return nil
	}

	account := refetched.GetEthDelegatedWalletByAddress(address)
	if account == nil {
		return nil
	}

	// Copied out of the refetched record, whose LinkedAccounts slice shares its backing array
	// with the cache entry GetUser just wrote.
	found := *account

	return &found
}

// Reports whether Axal may sign with a wallet, rendered as a linked account when it may and nil
// with a logged reason when it may not.
//
// This answers signing authority only — our key quorum among the wallet's signers, on ethereum.
// That is what POST /v1/wallets/{id}/rpc checks, so without it the wallet serves user-initiated
// signing and fails every Axal-initiated one, silently, at a time nobody is watching.
//
// Ownership is deliberately not answered here, because the two callers prove it differently and
// folding them together would weaken one of them. Provisioning derives the external id from the
// authenticated user, so the wallet it looks up or creates is theirs by construction. Signing is
// handed an address by the caller and cannot assume anything, so it asks Privy whose the wallet
// is. An earlier version checked the external id in both places, which looked uniform but
// inferred ownership from a convention of ours rather than from Privy — and would have refused
// the user's own wallet 0, which carries no external id.
func (cli *PrivyClient) signableAccountForWallet(privyId string, wallet *data.PrivyWallet) *data.LinkedAccount {
	signerID := cli.teeConfig.Privy.DelegatedActionsKeyId

	if !wallet.HasAdditionalSigner(signerID) || wallet.ChainType != "ethereum" {
		log.Errorf("Wallet cannot be signed for by Axal on behalf of user %s: expected signer %s among %s",
			privyId, signerID, summarizeWallet(wallet))
		return nil
	}

	// Ownership is proven by the caller, but this much is free and does not depend on Privy's
	// filter behaving: a wallet that carries an external id at all must carry one of this
	// user's. Wallet 0 carries none and is unaffected, while another user's purpose wallet
	// would be refused here even if the ownership filter had let it through.
	if wallet.ExternalID != "" && !data.ExternalIDBelongsToUser(wallet.ExternalID, privyId) {
		log.Errorf("Wallet carries another user's external id, refusing to sign for user %s: %s",
			privyId, summarizeWallet(wallet))
		return nil
	}

	account := linkedAccountFromWallet(wallet)

	return &account
}

// Renders a Privy wallet in the linked account shape the rest of the enclave and the HTTP API
// speak in, for the case where the user's record cannot supply it.
//
// Two fields have no counterpart on a wallet object and are filled in rather than copied:
//
//   - Delegated is set from the signer check. Privy reports no delegated flag on a wallet
//     object, and what the flag means everywhere in this codebase is "Axal can sign for this",
//     which an attached quorum is exactly.
//   - WalletIndex is set to unknownWalletIndex. The wallet does have an HD index — it is a real
//     embedded wallet — but only linked_accounts knows it, and this path exists precisely
//     because that record is not available yet. Zero is not usable as "unknown" here: it is the
//     index of the user's primary wallet, so it would name a different wallet.
func linkedAccountFromWallet(wallet *data.PrivyWallet) data.LinkedAccount {
	return data.LinkedAccount{
		WalletID:    wallet.ID,
		Type:        "wallet",
		Address:     wallet.Address,
		ChainType:   wallet.ChainType,
		PublicKey:   wallet.PublicKey,
		ExternalID:  wallet.ExternalID,
		Delegated:   true,
		WalletIndex: unknownWalletIndex,
	}
}

// Resolves the account for the wallet carrying an external id, or nil when Privy holds no
// wallet under it.
func (cli *PrivyClient) findWalletByExternalID(privyId string, user *data.PrivyUser, externalID string) (*data.LinkedAccount, *data.HttpError) {
	wallet, httpErr := cli.getWalletByExternalID(externalID)
	if httpErr != nil || wallet == nil {
		return nil, httpErr
	}

	return cli.accountForWallet(privyId, user, externalID, wallet)
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
		log.Infof("Wallet lookup: Privy holds no wallet under external id %s", externalID)
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
		log.Errorf("Wallet lookup API error: wallet under external id %s came back without an address: %s", externalID, summarizeWallet(&wallet))
		return nil, cli.createInternalServerError()
	}

	log.Infof("Wallet lookup: external id %s resolves to %s", externalID, summarizeWallet(&wallet))

	return &wallet, nil
}

// Fetches the user's wallet at an address, or nil when Privy holds no such wallet for them.
//
// The user_id filter is the ownership check, and it is why this is a list rather than the
// by-address lookup it replaced. Privy answers from its own ownership graph — the wallet's
// owner quorum resolving to this user — so nothing here depends on a naming convention of
// ours. That matters because the address is caller-supplied: without Privy's answer, an
// authenticated user could name any address in the app and be signed for.
//
// A quorum-owned wallet is invisible to the user record, so this is also the only way to see
// one for signing.
func (cli *PrivyClient) findUserWalletByAddress(privyId string, address string) (*data.PrivyWallet, *data.HttpError) {
	wallets, httpErr := cli.listUserWallets(privyId, "address", address)
	if httpErr != nil {
		return nil, httpErr
	}

	for _, wallet := range wallets {
		if wallet == nil {
			continue
		}

		// The filter is re-checked rather than trusted. If Privy ever widened it, or ignored a
		// combination of filters, a wallet at another address would be a wallet we were not
		// asked about.
		if strings.EqualFold(wallet.Address, address) {
			return wallet, nil
		}
	}

	log.Infof("Wallet lookup: user %s holds no wallet at %s", privyId, address)

	return nil, nil
}

// Fetches the wallets Privy considers a user's, narrowed by one additional filter.
func (cli *PrivyClient) listUserWallets(privyId string, filterKey string, filterValue string) ([]*data.PrivyWallet, *data.HttpError) {
	query := neturl.Values{}
	query.Set("user_id", privyId)
	query.Set(filterKey, filterValue)

	url := fmt.Sprintf("%s%s?%s", cli.baseUrl, WALLETS_PATH.Build(), query.Encode())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("failed to create wallet list request: %v", err)
		return nil, cli.createInternalServerError()
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("error sending the wallet list request: %v", err)
		return nil, cli.createInternalServerError()
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Errorf("Wallet list API error: privy returned status %d for user %s (%s=%s)", res.StatusCode, privyId, filterKey, filterValue)
		return nil, handlePrivyError(res)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading wallet list response body: %v", err)
		return nil, cli.createInternalServerError()
	}

	var listed data.WalletListResponse
	if err := json.Unmarshal(body, &listed); err != nil {
		log.Errorf("unable to unmarshal wallet list response: %v", err)
		return nil, cli.createInternalServerError()
	}

	log.Infof("Wallet list: user %s has %d wallet(s) matching %s=%s", privyId, len(listed.Data), filterKey, filterValue)

	return listed.Data, nil
}

// Creates the wallet at Privy and returns it.
//
// The wallet is created on the wallet API rather than on the user's own wallets collection:
// that one only provisions the embedded wallet a user does not yet have, and answers 200
// without creating anything for a chain type the user already holds — which is silent
// failure for a second wallet.
func (cli *PrivyClient) postCreateWallet(privyId string, externalID string) (*data.PrivyWallet, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, WALLETS_PATH.Build())

	walletCreateReq := data.NewCreateDelegatedEthWalletRequest(privyId, cli.teeConfig.Privy.DelegatedActionsKeyId, externalID)

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

	// The request carries no secret: a chain type, an external id, the user's DID and the
	// signer's key quorum id, which is a public identifier and not a key. Logging it is what
	// makes a 4xx answerable — the rejection is almost always about a field in here.
	log.Infof("Wallet create: POST %s %s", url, string(requestBody))

	cli.addStandardPrivyHeaders(req)

	// Derived from the external id, so it is the same key every time this wallet is
	// requested. Privy holds idempotency records for 24 hours, which covers the retry window
	// our own guards cannot see. It is not the last line of defence — the external id is
	// unique per app, so a duplicate create collides there even once this record has expired.
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

	var wallet data.PrivyWallet
	if err := json.Unmarshal(body, &wallet); err != nil {
		log.Errorf("unable to unmarshal create wallet response: %v", err)
		return nil, cli.createInternalServerError()
	}

	if wallet.ID == "" || wallet.Address == "" {
		log.Errorf("Create wallet API error: created wallet for user %s came back without an id or address: %s", privyId, string(body))
		return nil, cli.createInternalServerError()
	}

	log.Infof("Wallet create: Privy created %s for user %s", summarizeWallet(&wallet), privyId)

	return &wallet, nil
}

// Returns a copy of the user with a set of linked accounts folded in.
//
// The copy is not optional. GetUser hands back a shallow copy whose LinkedAccounts slice still
// shares its backing array with the cached entry, so merging in place would reach through and
// mutate the cache underneath other readers.
func mergedUser(user *data.PrivyUser, accounts []*data.LinkedAccount) *data.PrivyUser {
	updated := *user
	updated.LinkedAccounts = append([]data.LinkedAccount(nil), user.LinkedAccounts...)
	mergeLinkedAccounts(&updated, accounts)

	return &updated
}

// Renders a Privy wallet for a log line: what it is, who owns it, and who may sign for it.
//
// The signer list is the point. Whether our key quorum is attached is the difference between
// a wallet Axal can rebalance from and one only its user can ever move, and it is not
// visible anywhere else in the logs.
func summarizeWallet(wallet *data.PrivyWallet) string {
	signers := make([]string, 0, len(wallet.AdditionalSigners))
	for _, signer := range wallet.AdditionalSigners {
		if signer != nil {
			signers = append(signers, signer.SignerID)
		}
	}

	return fmt.Sprintf("{id:%q address:%q chain:%q external_id:%q owner_id:%q signers:[%s]}",
		wallet.ID, wallet.Address, wallet.ChainType, wallet.ExternalID, wallet.OwnerID, strings.Join(signers, " "))
}

// Renders the identifying fields of a user's linked accounts for a log line.
//
// Deliberately not the raw record: linked accounts carry the user's email and wallet
// addresses, and neither is needed to work out why a wallet was not found on the user.
func summarizeUserAccounts(user *data.PrivyUser) string {
	if len(user.LinkedAccounts) == 0 {
		return "[]"
	}

	parts := make([]string, 0, len(user.LinkedAccounts))
	for _, acc := range user.LinkedAccounts {
		parts = append(parts, fmt.Sprintf("{id:%q type:%q chain:%q index:%d delegated:%t external_id:%q}",
			acc.WalletID, acc.Type, acc.ChainType, acc.WalletIndex, acc.Delegated, acc.ExternalID))
	}

	return "[" + strings.Join(parts, " ") + "]"
}
