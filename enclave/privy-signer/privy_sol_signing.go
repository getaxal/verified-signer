package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// User signing - JWT auth only, privy_id extracted from JWT.
//
// The request names the solana wallet to sign with, and it is resolved against the JWT's
// user: an address belonging to somebody else is not found on this user and is rejected.
func (cli *PrivyClient) UserSolSignTransaction(signReq *data.UserSolSignTransactionRequest, authString string) (*data.SolSignTransactionResponse, *data.HttpError) {
	// Validate JWT and get privy_id
	privyId, httpErr := cli.ValidateUserAuthForSigningRequest(authString)
	if httpErr != nil {
		log.Errorf("invalid user auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	return cli.solSignTransaction(privyId, signReq.WalletAddress, signReq.GetPrivySignData())
}

// Axal signing - HMAC auth only, privy_id from request body
func (cli *PrivyClient) AxalSolSignTransaction(signReq *data.AxalSolSignTransactionRequest, hmacSignature string) (*data.SolSignTransactionResponse, *data.HttpError) {
	// Validate HMAC. The preimage covers the wallet and the user, so both are authenticated
	// by the time they are used below.
	if httpErr := cli.ValidateAxalSolSignTransactionAuth(hmacSignature, signReq); httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	return cli.solSignTransaction(signReq.PrivyID, signReq.WalletAddress, signReq.GetPrivySignData())
}

// Signs a solana transaction with one of a user's delegated solana wallets. The caller has
// already established who the user is; this establishes that the wallet is theirs.
//
// The transaction is signed, not sent: what comes back is the serialized transaction with
// this wallet's signature filled in, and broadcasting it is the caller's business.
func (cli *PrivyClient) solSignTransaction(privyId string, walletAddress string, privyData data.PrivySolSignTransactionData) (*data.SolSignTransactionResponse, *data.HttpError) {
	wallet, httpErr := cli.resolveDelegatedSolWallet(privyId, walletAddress)
	if httpErr != nil {
		return nil, httpErr
	}

	var resp data.SolSignTransactionResponse
	if httpErr := cli.executePrivySigningRequestForWallet(privyData, wallet.WalletID, &resp); httpErr != nil {
		return nil, httpErr
	}

	// A 200 that carries no transaction is not a signature. Passing it on would hand the
	// caller an empty string to broadcast, and the failure would surface somewhere with no
	// trace of where it began.
	if resp.Data.SignedTransaction == "" {
		log.Errorf("Solana signing API error: privy answered 200 without a signed transaction for user %s", privyId)
		return nil, cli.createInternalServerError()
	}

	return &resp, nil
}
