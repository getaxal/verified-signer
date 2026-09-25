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

	return cli.accountForWallet(privyId, externalID, wallet)
}

// Turns a Privy wallet into the linked account the rest of the enclave works with, or fails
// if the wallet is not one Axal can sign for.
//
// Two sources are combined because each is authoritative for a different half of the answer.
// The wallet object knows which signers are attached; only the user record carries the
// wallet_index and the delegated flag that the signing path resolves addresses against. So
// the checks that decide whether the wallet is usable are made against the wallet object,
// and the record returned comes from the user.
func (cli *PrivyClient) accountForWallet(privyId string, externalID string, wallet *data.PrivyWallet) (*data.LinkedAccount, *data.HttpError) {
	// Assert the signer rather than trusting that Privy applied what we asked for. A wallet
	// without our quorum attached would serve user-initiated signing and fail every
	// Axal-initiated one — rebalancing and reward claiming — silently, at a time nobody is
	// watching.
	signerID := cli.teeConfig.Privy.DelegatedActionsKeyId
	if !wallet.HasAdditionalSigner(signerID) || wallet.ChainType != "ethereum" {
		log.Errorf("Create wallet API error: wallet for user %s cannot be signed for by Axal: expected signer %s among %s",
			privyId, signerID, summarizeWallet(wallet))
		return nil, cli.createInternalServerError()
	}

	account, httpErr := cli.linkedAccountForAddress(privyId, wallet.Address)
	if httpErr != nil {
		return nil, httpErr
	}

	if account == nil {
		// Our quorum is attached, so Privy would accept a signature for this wallet, but the
		// signing path resolves addresses out of the user record and this wallet is not in it
		// as a delegated eth wallet. Returning it would hand back an address that cannot be
		// signed for until the record catches up.
		log.Errorf("Create wallet API error: wallet under external id %s is not listed as a delegated eth wallet on user %s: %s",
			externalID, privyId, summarizeWallet(wallet))
		return nil, cli.createInternalServerError()
	}

	log.Infof("User %s has wallet %s at index %d for external id %s", privyId, wallet.ID, account.WalletIndex, externalID)

	return account, nil
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

// Finds the user's delegated eth wallet at an address, refetching the user once when the
// cached record does not carry it.
//
// The refetch is what makes this usable straight after a create: the cached record was read
// before the wallet existed, so a miss against it is expected rather than conclusive. A miss
// against a freshly fetched record is conclusive, and the nil it returns means the user does
// not hold this wallet as a delegated eth wallet.
func (cli *PrivyClient) linkedAccountForAddress(privyId string, address string) (*data.LinkedAccount, *data.HttpError) {
	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	if account := user.GetEthDelegatedWalletByAddress(address); account != nil {
		return account, nil
	}

	log.Infof("Wallet %s is not on the cached record for user %s, refetching from Privy", address, privyId)

	cli.InvalidateUser(privyId)

	user, httpErr = cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	account := user.GetEthDelegatedWalletByAddress(address)
	if account == nil {
		log.Warnf("User %s does not hold %s as a delegated eth wallet (accounts %s)", privyId, address, summarizeUserAccounts(user))
		return nil, nil
	}

	// GetUser has already cached this record, so the cache is consistent with what is
	// returned and needs no second write.
	return account, nil
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
