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

// Generic function to handle HTTP requests and responses for signing requests
func (cli *PrivyClient) executePrivySigningRequest(txRequest interface{}, privyId string, response interface{}) *data.HttpError {
	// Fetch the wallet id by fetching user
	user, httpErr := cli.GetUser(privyId)
	if httpErr != nil {
		return httpErr
	}

	ethWallet := user.GetUsersEthDelegatedWallet()
	if ethWallet == nil || ethWallet.WalletID == "" {
		log.Errorf("Eth secp256k1 sign API error user %s does not have a delegated eth wallet", user.PrivyID)
		return &data.HttpError{
			Code: http.StatusBadRequest,
			Message: data.Message{
				Message: "user does not have an delegated eth wallet",
			},
		}
	}

	req, err := cli.prepSigningTxRequest(txRequest, ethWallet.WalletID)
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
