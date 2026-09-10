package privysigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

	// Recorded before the create so the new wallet can be told apart from the ones the
	// response may echo back alongside it.
	known := make(map[string]bool, len(user.LinkedAccounts))
	for _, acc := range user.LinkedAccounts {
		if acc.WalletID != "" {
			known[acc.WalletID] = true
		}
	}

	createResp, httpErr := cli.postCreateWallet(privyId, externalID)
	if httpErr != nil {
		return nil, httpErr
	}

	wallet := selectCreatedWallet(createResp.LinkedAccounts, externalID, known)
	if wallet == nil {
		log.Errorf("Create wallet API error: created wallet for user %s could not be identified in the response", privyId)
		return nil, cli.createInternalServerError()
	}

	// Assert delegation rather than trusting the Privy default. A wallet created without
	// our signer attached would serve user-initiated signing and fail every Axal-initiated
	// one — rebalancing and reward claiming — silently, at a time nobody is watching.
	if !wallet.Delegated || wallet.ChainType != "ethereum" {
		log.Errorf("Create wallet API error: wallet created for user %s is not a delegated eth wallet", privyId)
		return nil, cli.createInternalServerError()
	}

	// The signing path resolves addresses against the cached user, so leaving a
	// pre-creation snapshot in place would make this wallet unusable until the TTL
	// expired — and because the enclave never falls back to another wallet, that surfaces
	// as a hard rejection rather than a wrong signature.
	cli.InvalidateUser(privyId)

	return wallet, nil
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
