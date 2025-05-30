package privysigner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	enclave "verified-signer-enclave"
	"verified-signer-enclave/network"
	authorizationsignature "verified-signer-enclave/privy-signer/authorization_signature"
	"verified-signer-enclave/privy-signer/data"

	"github.com/axal/verified-signer-common/aws"

	log "github.com/sirupsen/logrus"
)

type PrivyClient struct {
	baseUrl       string
	client        *http.Client
	privyConfig   *PrivyConfig
	authorization string
}

// Inits a new Privy Client with a custom Transport Layer service that routes https through the privyAPIVsockPort.
func InitNewPrivyClient(portsCfg *enclave.PortConfig, awsConfig *aws.AWSConfig, environment string) (*PrivyClient, error) {
	// Setup Privy Config for privy api details
	privyConfig, err := InitPrivyConfig(*awsConfig, portsCfg.AWSSecretManagerVsockPort, environment)

	if err != nil {
		log.Errorf("Could not fetch Privy config due to err: %v", err)
		return nil, err
	}

	// Setup a new Http client for Privy API calls
	privyClient := network.InitHttpsClientWithTLSVsockTransport(portsCfg.PrivyAPIVsockPort, "api.privy.io")

	username := privyConfig.AppID
	password := privyConfig.AppSecret

	authorization := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	return &PrivyClient{
		baseUrl:       "https://api.privy.io",
		client:        privyClient,
		privyConfig:   privyConfig,
		authorization: authorization,
	}, nil

}

// Adds the standard API headers for most Privy API calls
func (cli *PrivyClient) addStandardPrivyHeaders(req *http.Request) {
	req.Header.Add("privy-app-id", cli.privyConfig.AppID)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+cli.authorization)
}

// Preps Eth Transaction signing request by preparing the body and the headers.
// The headers are:
//
//	{
//	    "privy-app_id" : "your-app-id"
//	    "authorization" : "privy-app-id:privy-app-secret" //base64 encoded
//		"Content-Type" : "application/json"
//		"privy-authorization-signature" : "your-auth-signature" //get it using authorizationsignature.GetAuthorizationSignature
//	}
func (cli *PrivyClient) prepEthSigningTxRequest(body interface{}, walletId string) (*http.Request, error) {
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
	signature, err := authorizationsignature.GetAuthorizationSignature(body, req.Method, cli.privyConfig.DelegatedActionsKey, url, cli.privyConfig.AppID)
	if err != nil {
		log.Errorf("Error getting authorization signature: %v", err)
		return nil, err
	}

	req.Header.Add("privy-authorization-signature", signature)

	return req, nil
}

// Gets a user given a Privy userID
func (cli *PrivyClient) GetUser(userId string) (*data.PrivyUser, error) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, GET_USER_PATH.Build(userId))

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return nil, err
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return nil, err
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		log.Printf("Warning: Received status code %d", res.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return nil, err
	}

	var user data.PrivyUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("deserializing JSON: %w", err)
	}

	return &user, nil
}

// Signs a transaction using the eth_signTransaction method
func (cli *PrivyClient) EthSignTransaction(txRequest *data.EthSignTransactionRequest, wallet_id string) error {
	req, err := cli.prepEthSigningTxRequest(*txRequest, wallet_id)

	if err != nil {
		log.Errorf("Error initiating signing request")
		return err
	}

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return err
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		log.Warnf("Warning: Received status code %d", res.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return err
	}

	var resp interface{}
	json.Unmarshal(body, &resp)

	log.Infof("Resp body :%+v", resp)

	return nil
}

// Signs and sends a transaction using the eth_sendTransaction method. A successful response indicates that the transaction has been broadcasted to the network.
// Transactions may get broadcasted but still fail to be confirmed by the network.
func (cli *PrivyClient) EthSendTransaction(txRequest *data.EthSendTransactionRequest, wallet_id string) error {
	req, err := cli.prepEthSigningTxRequest(*txRequest, wallet_id)

	if err != nil {
		log.Errorf("Error initiating signing request")
		return err
	}

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return err
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		log.Warnf("Warning: Received status code %d", res.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return err
	}

	var resp interface{}
	json.Unmarshal(body, &resp)

	log.Infof("Resp body :%+v", resp)

	return nil
}

// Signs a transaction using the eth personal sign method
func (cli *PrivyClient) EthPersonalSign(txRequest *data.EthPersonalSignRequest, wallet_id string) error {
	req, err := cli.prepEthSigningTxRequest(*txRequest, wallet_id)

	if err != nil {
		log.Errorf("Error initiating signing request")
		return err
	}

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return err
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		log.Warnf("Warning: Received status code %d", res.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return err
	}

	var resp interface{}
	json.Unmarshal(body, &resp)

	log.Infof("Resp body :%+v", resp)

	return nil
}
