package privysigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
)

// userFetchResult carries both the user and the structured HttpError through the
// singleflight.Group, since singleflight.Do only exposes a plain error channel.
type userFetchResult struct {
	user    *data.PrivyUser
	httpErr *data.HttpError
}

// Gets a user given a Privy userID. It also checks to see if the user already has a delagted eth wallet, if it does not it will create one for them.
// The same is then done for a solana wallet, except that failing to create that one does not fail the call.
//
// Concurrent first-time calls for the same privyId are collapsed via a per-privyId
// singleflight group: they share ONE GET and AT MOST ONE create-wallet POST per chain. This
// closes the check-then-create TOCTOU window where two callers both missed the
// cache, both saw a wallet-less user, and both POSTed -> two Privy wallets.
func (cli *PrivyClient) GetUser(privyId string) (*data.PrivyUser, *data.HttpError) {
	// Fast path: serve straight from cache without entering the single-flight group.
	if item := cli.userCache.Get(privyId); item != nil {
		log.Infof("Cache Hit: %s", privyId)
		value := item.Value()
		return &value, nil
	}

	// Cache miss: only one goroutine per privyId runs fetchAndCacheUser; the rest
	// block and receive the same shared result.
	res, _, _ := cli.userFetchGroup.Do(privyId, func() (interface{}, error) {
		user, httpErr := cli.fetchAndCacheUser(privyId)
		return userFetchResult{user: user, httpErr: httpErr}, nil
	})

	result := res.(userFetchResult)
	if result.httpErr != nil {
		return nil, result.httpErr
	}

	// Hand each collapsed caller its own *PrivyUser rather than the single shared
	// pointer from fetchAndCacheUser. This matches the cache fast-path semantics
	// (which returns &value, a per-caller copy) so a downstream mutation can never
	// race across the N goroutines that collapsed onto this single flight.
	user := *result.user
	return &user, nil
}

// fetchAndCacheUser performs the actual GET + create-wallet-if-needed + cache fill.
// It runs inside the singleflight critical section for a given privyId.
func (cli *PrivyClient) fetchAndCacheUser(privyId string) (*data.PrivyUser, *data.HttpError) {
	// Re-check the cache inside the critical section: a concurrent winner that
	// finished just before us may already have populated it. singleflight only
	// dedups overlapping calls, not strictly sequential ones.
	if item := cli.userCache.Get(privyId); item != nil {
		log.Infof("Cache Hit (in-flight): %s", privyId)
		value := item.Value()
		return &value, nil
	}

	url := fmt.Sprintf("%s%s", cli.baseUrl, GET_USER_PATH.Build(privyId))

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		httpErr := handlePrivyError(res)
		return nil, httpErr
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	var user data.PrivyUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	userWithWallet, httpErr := cli.createUserWalletsIfNotExists(user, privyId)

	if httpErr != nil {
		return nil, httpErr
	}

	cli.createUserSolWalletIfNotExists(userWithWallet, privyId)

	cli.cacheUser(privyId, userWithWallet)

	return userWithWallet, nil
}

// Writes a user record into the cache.
//
// The signing path resolves wallet addresses out of this record, so whatever is stored
// here is what the enclave believes a user's wallets to be until it expires.
func (cli *PrivyClient) cacheUser(privyId string, user *data.PrivyUser) {
	cli.userCache.Set(privyId, *user, userRecordTTL(user))
}

// How long a user record may be served before Privy is asked again.
//
// A record that is still owed a solana wallet is kept only briefly. Provisioning that wallet
// is not allowed to fail the read, so the record is cached without it — and at the full TTL
// that would turn one failed create into two hours of a user with no solana wallet. Expiring
// it early is what retries the create. The window is short enough to heal a blip quickly and
// long enough that a create which keeps failing costs one read and one create per user per
// window, rather than one of each per signature.
func userRecordTTL(user *data.PrivyUser) time.Duration {
	if user.NeedsSolWallet() {
		return solWalletRetryTTL
	}

	return ttlcache.DefaultTTL
}

// Checks to see if a user has a delegated eth wallet, if the user does not it will create one for them
func (cli *PrivyClient) createUserWalletsIfNotExists(user data.PrivyUser, userId string) (*data.PrivyUser, *data.HttpError) {
	if user.GetUsersEthDelegatedWallet() != nil {
		log.Infof("User %s has a linked address", userId)
		return &user, nil
	}

	log.Infof("User %s doesnt have a linked address, creating one for them", userId)

	accounts, httpErr := cli.postCreateEmbeddedWallet(userId, data.NewCreateEthWalletRequest(cli.teeConfig.Privy.DelegatedActionsKeyId))
	if httpErr != nil {
		return nil, httpErr
	}

	// Keep every account the response carries, not just the first delegated eth wallet: a
	// user may hold several wallets and callers select between them by address, so
	// dropping the rest here would make them unsignable.
	mergeLinkedAccounts(&user, accounts)

	// Assert delegation actually took rather than trusting the Privy default. A wallet
	// created without our signer attached would serve user-initiated signing and fail
	// every Axal-initiated one, silently, at a time nobody is watching.
	if user.GetUsersEthDelegatedWallet() == nil {
		log.Errorf("created wallet for user %s did not come back delegated", userId)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	return &user, nil
}

// Checks to see if a user has a delegated solana wallet, and creates one for them if they
// hold no solana wallet at all. The wallet is folded into the user in place.
//
// Unlike the eth wallet above, nothing here fails the read. Every signature on every chain
// starts by reading the user, so an error from this step would take eth signing down with it
// — for a wallet most requests never touch. A user who comes out of here without a solana
// wallet is still a user who can sign on eth; the solana routes refuse them with their own
// error, and the record is cached briefly so the create is tried again (see userRecordTTL).
//
// It is a separate create from the eth one for the same reason: sent together, a rejection of
// the solana wallet would reject the eth wallet with it.
func (cli *PrivyClient) createUserSolWalletIfNotExists(user *data.PrivyUser, userId string) {
	if user.GetUsersSolDelegatedWallet() != nil {
		return
	}

	// The create endpoint only provisions the embedded wallet a user does not yet have, and
	// answers 200 without creating anything for a chain type they already hold. So for a user
	// whose solana wallet was made without our signer there is nothing to ask for: attaching
	// a signer to an existing wallet takes its owner's authorization, which only the user's
	// own client can supply.
	if user.HasEmbeddedSolWallet() {
		log.Warnf("User %s holds an embedded solana wallet that is not delegated to Axal; solana signing stays unavailable for them until they delegate it", userId)
		return
	}

	log.Infof("User %s doesnt have a solana wallet, creating one for them", userId)

	accounts, httpErr := cli.postCreateEmbeddedWallet(userId, data.NewCreateSolWalletRequest(cli.teeConfig.Privy.DelegatedActionsKeyId))
	if httpErr != nil {
		log.Errorf("could not create a solana wallet for user %s, continuing without one: %d %s", userId, httpErr.Code, httpErr.Message.Message)
		return
	}

	// Only the solana wallets are taken. The response is the whole user, and the rest of it
	// was read a moment ago — folding it in again would add nothing but a second copy of every
	// account that carries no id to be matched on, such as an email.
	mergeLinkedAccounts(user, solWalletAccounts(accounts))

	// Asserted for the same reason as the eth wallet, and logged rather than returned for the
	// reason above.
	if user.GetUsersSolDelegatedWallet() == nil {
		log.Errorf("created solana wallet for user %s did not come back delegated", userId)
	}
}

// The solana wallets among a set of linked accounts.
func solWalletAccounts(accounts []*data.LinkedAccount) []*data.LinkedAccount {
	wallets := make([]*data.LinkedAccount, 0, 1)
	for _, acc := range accounts {
		if acc != nil && acc.Type == "wallet" && acc.ChainType == data.ChainTypeSolana {
			wallets = append(wallets, acc)
		}
	}

	return wallets
}

// Asks Privy to provision an embedded wallet on the user's own wallets collection, and
// returns the linked accounts the response carries.
//
// This endpoint provisions the wallet a user does not yet have for a chain type — the one at
// HD index 0. It cannot add a second wallet on a chain; purpose-built wallets are created
// with postCreateWallet instead.
func (cli *PrivyClient) postCreateEmbeddedWallet(userId string, walletCreateReq *data.CreateWalletRequest) ([]*data.LinkedAccount, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, CREATE_WALLET_PATH.Build(userId))

	requestBody, err := json.Marshal(walletCreateReq)

	if err != nil {
		log.Errorf("failed to marshal wallet create request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))

	if err != nil {
		log.Errorf("failed to create request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)

	if err != nil {
		log.Errorf("error sending the client request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		httpErr := handlePrivyError(res)
		return nil, httpErr
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	var createWalletResp data.CreateWalletResponse
	if err := json.Unmarshal(body, &createWalletResp); err != nil {
		log.Errorf("unable to marshall response data:%v", string(body))
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	return createWalletResp.LinkedAccounts, nil
}

// Folds the linked accounts from a create-wallet response into the user, keyed by wallet
// id.
//
// Privy may echo the user's full account set rather than only the wallet just created, so
// a plain append would duplicate wallets we already hold. Matching on wallet id keeps the
// merge idempotent and lets an existing entry be refreshed in place.
func mergeLinkedAccounts(user *data.PrivyUser, accounts []*data.LinkedAccount) {
	positions := make(map[string]int, len(user.LinkedAccounts))
	for i, acc := range user.LinkedAccounts {
		if acc.WalletID != "" {
			positions[acc.WalletID] = i
		}
	}

	for _, acc := range accounts {
		if acc == nil {
			continue
		}

		if i, seen := positions[acc.WalletID]; seen && acc.WalletID != "" {
			user.LinkedAccounts[i] = *acc
			continue
		}

		user.LinkedAccounts = append(user.LinkedAccounts, *acc)
		if acc.WalletID != "" {
			positions[acc.WalletID] = len(user.LinkedAccounts) - 1
		}
	}
}

// Drops a user's cached record, forcing the next read to come from Privy.
func (cli *PrivyClient) InvalidateUser(privyId string) {
	cli.userCache.Delete(privyId)
}
