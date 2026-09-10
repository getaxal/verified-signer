package privysigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	authorizationsignature "github.com/getaxal/verified-signer/enclave/privy-signer/authorization_signature"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// Preps Transaction signing request by preparing the body and the headers.
// The headers are:
//
//	{
//	    "privy-app_id" : "your-app-id"
//	    "authorization" : "privy-app-id:privy-app-secret" //base64 encoded
//		"Content-Type" : "application/json"
//		"privy-authorization-signature" : "your-auth-signature" //get it using authorizationsignature.GetAuthorizationSignature
//	}
func (cli *PrivyClient) prepSigningTxRequest(body interface{}, walletId string) (*http.Request, error) {
	// format url
	url := fmt.Sprintf("%s%s", cli.baseUrl, SIGN_TX_PATH.Build(walletId))

	// attach json body
	jsonData, err := json.Marshal(body)

	if err != nil {
		log.Errorf("Error marshalling tx request: %v", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))

	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return nil, err
	}

	// Add basic headers
	cli.addStandardPrivyHeaders(req)

	// Add auth signature header
	signature, err := authorizationsignature.GetAuthorizationSignature(body, req.Method, cli.teeConfig.Privy.DelegatedActionsKey, url, cli.teeConfig.Privy.AppID)
	if err != nil {
		log.Errorf("Error getting authorization signature: %v", err)
		return nil, err
	}

	req.Header.Add("privy-authorization-signature", signature)

	return req, nil
}

// Resolves the wallet a signing request names and verifies it belongs to the user the
// request authenticated as.
//
// The enclave never infers a signer. A user may hold several delegated eth wallets, so
// an address that is not one of theirs is rejected rather than served by a different
// wallet: a signature from the wrong key produces a user operation that fails validation
// on chain, which is far more expensive to diagnose than a 4xx. This is also the
// ownership check, and it is why requests name a wallet by address rather than by index
// or by Privy wallet id, neither of which we can verify against the user.
func (cli *PrivyClient) resolveDelegatedWallet(privyId string, walletAddress string) (*data.LinkedAccount, *data.HttpError) {
	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return nil, httpErr
	}

	wallet := user.GetEthDelegatedWalletByAddress(walletAddress)
	if wallet == nil || wallet.WalletID == "" {
		log.Errorf("Signing API error: requested wallet is not a delegated eth wallet of user %s", privyId)
		return nil, &data.HttpError{
			Code: http.StatusBadRequest,
			Message: data.Message{
				Message: "requested wallet is not a delegated eth wallet for this user",
			},
		}
	}

	return wallet, nil
}

// Generic function to handle HTTP requests and responses for signing requests. The
// wallet is named by the caller and verified against the user before anything is signed.
func (cli *PrivyClient) executePrivySigningRequest(txRequest interface{}, privyId string, walletAddress string, response interface{}) *data.HttpError {
	wallet, httpErr := cli.resolveDelegatedWallet(privyId, walletAddress)
	if httpErr != nil {
		return httpErr
	}

	return cli.executePrivySigningRequestForWallet(txRequest, wallet.WalletID, response)
}

func (cli *PrivyClient) executePrivySigningRequestForWallet(txRequest interface{}, walletID string, response interface{}) *data.HttpError {
	req, err := cli.prepSigningTxRequest(txRequest, walletID)
	if err != nil {
		log.Errorf("Error initiating signing request: %v", err)
		return cli.createInternalServerError()
	}

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return cli.createInternalServerError()
	}
	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		log.Errorf("Received status code %d", res.StatusCode)
		httpErr := handlePrivyError(res)
		return httpErr
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return cli.createInternalServerError()
	}

	// Unmarshal response
	err = json.Unmarshal(body, response)
	if err != nil {
		log.Errorf("Error unmarshalling response body: %v", err)
		return cli.createInternalServerError()
	}

	return nil
}
