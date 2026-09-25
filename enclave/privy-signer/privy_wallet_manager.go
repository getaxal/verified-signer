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
	existing, httpErr := cli.findWalletByExternalID(privyId, externalID)
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

		recovered, lookupErr := cli.findWalletByExternalID(privyId, externalID)
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

	account, httpErr := cli.accountForWallet(privyId, externalID, wallet)
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
func (cli *PrivyClient) accountForWallet(privyId string, externalID string, wallet *data.PrivyWallet) (*data.LinkedAccount, *data.HttpError) {
	account := cli.signableAccountForWallet(privyId, wallet)
	if account == nil {
		log.Errorf("Create wallet API error: the wallet under external id %s is not usable for user %s", externalID, privyId)
		return nil, cli.createInternalServerError()
	}

	log.Infof("Wallet %s (%s) is signable by Axal for user %s under external id %s",
		wallet.ID, wallet.Address, privyId, wallet.ExternalID)

	return account, nil
}

// Reports whether a wallet is one Axal may sign with on a user's behalf, rendered as a linked
// account when it is and nil with a logged reason when it is not.
//
// This is the single definition of that question, shared by provisioning and by signing, so the
// two cannot drift into disagreeing about which wallets are usable. Two conditions, each
// covering a different failure:
//
//   - our key quorum is among the wallet's signers, on ethereum. This is what
//     POST /v1/wallets/{id}/rpc checks, so without it the wallet serves user-initiated signing
//     and fails every Axal-initiated one, silently.
//   - the external id is one this enclave assigned to this user. This is the ownership check.
//     A quorum-owned wallet is not among the user's linked accounts, so the record that usually
//     proves a wallet is theirs cannot speak for it, and without a check in its place an
//     authenticated user could name any address in the app and be signed for.
func (cli *PrivyClient) signableAccountForWallet(privyId string, wallet *data.PrivyWallet) *data.LinkedAccount {
	signerID := cli.teeConfig.Privy.DelegatedActionsKeyId

	if !wallet.HasAdditionalSigner(signerID) || wallet.ChainType != "ethereum" {
		log.Errorf("Wallet cannot be signed for by Axal on behalf of user %s: expected signer %s among %s",
			privyId, signerID, summarizeWallet(wallet))
		return nil
	}

	if !data.ExternalIDBelongsToUser(wallet.ExternalID, privyId) {
		log.Errorf("Wallet was not provisioned for user %s, refusing to treat it as theirs: %s",
			privyId, summarizeWallet(wallet))
		return nil
	}

	account := linkedAccountFromWallet(wallet)

	return &account
}

// Renders a Privy wallet in the linked account shape the rest of the enclave and the HTTP API
// speak in.
//
// Delegated is set from the signer check rather than copied from Privy, which does not report
// one for a quorum-owned wallet. What the flag means everywhere in this codebase is "Axal can
// sign for this", and an attached quorum is exactly that.
//
// WalletIndex is left at zero because these wallets have no HD index — only the user's embedded
// wallet does, and it is the one at index 0.
func linkedAccountFromWallet(wallet *data.PrivyWallet) data.LinkedAccount {
	return data.LinkedAccount{
		WalletID:   wallet.ID,
		Type:       "wallet",
		Address:    wallet.Address,
		ChainType:  wallet.ChainType,
		PublicKey:  wallet.PublicKey,
		ExternalID: wallet.ExternalID,
		Delegated:  true,
	}
}

// Resolves the account for the wallet carrying an external id, or nil when Privy holds no
// wallet under it.
func (cli *PrivyClient) findWalletByExternalID(privyId string, externalID string) (*data.LinkedAccount, *data.HttpError) {
	wallet, httpErr := cli.getWalletByExternalID(externalID)
	if httpErr != nil || wallet == nil {
		return nil, httpErr
	}

	return cli.accountForWallet(privyId, externalID, wallet)
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

// Fetches the wallet at an address, or nil when Privy holds none.
//
// This is how a wallet that is not on the user's record is resolved for signing, which is given
// an address and needs the wallet id behind it. Answering what an address is and deciding whose
// it is are kept apart: this does the first, and the caller must do the second.
func (cli *PrivyClient) getWalletByAddress(address string) (*data.PrivyWallet, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, GET_WALLET_BY_ADDRESS_PATH.Build())

	requestBody, err := json.Marshal(data.WalletByAddressRequest{Address: address})
	if err != nil {
		log.Errorf("failed to marshal wallet address lookup request: %v", err)
		return nil, cli.createInternalServerError()
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Errorf("failed to create wallet address lookup request: %v", err)
		return nil, cli.createInternalServerError()
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("error sending the wallet address lookup request: %v", err)
		return nil, cli.createInternalServerError()
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		log.Infof("Wallet lookup: Privy holds no wallet at %s", address)
		return nil, nil
	}

	if res.StatusCode != http.StatusOK {
		log.Errorf("Wallet lookup API error: privy returned status %d for address %s", res.StatusCode, address)
		return nil, handlePrivyError(res)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading wallet address lookup response body: %v", err)
		return nil, cli.createInternalServerError()
	}

	var wallet data.PrivyWallet
	if err := json.Unmarshal(body, &wallet); err != nil {
		log.Errorf("unable to unmarshal wallet address lookup response: %v", err)
		return nil, cli.createInternalServerError()
	}

	if wallet.ID == "" {
		log.Errorf("Wallet lookup API error: wallet at %s came back without an id: %s", address, summarizeWallet(&wallet))
		return nil, cli.createInternalServerError()
	}

	log.Infof("Wallet lookup: address %s resolves to %s", address, summarizeWallet(&wallet))

	return &wallet, nil
}

// Creates the wallet at Privy and returns it.
//
// The wallet is created on the wallet API rather than on the user's own wallets collection:
// that one only provisions the embedded wallet a user does not yet have, and answers 200
// without creating anything for a chain type the user already holds — which is silent
// failure for a second wallet.
func (cli *PrivyClient) postCreateWallet(privyId string, externalID string) (*data.PrivyWallet, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, CREATE_OWNED_WALLET_PATH.Build())

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
