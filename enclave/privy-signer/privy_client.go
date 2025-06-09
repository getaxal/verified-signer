package privysigner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/getaxal/verified-signer/enclave/network"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"

	authorizationsignature "github.com/getaxal/verified-signer/enclave/privy-signer/authorization_signature"

	"github.com/getaxal/verified-signer/common/aws"

	log "github.com/sirupsen/logrus"
)

var PrivyCli *PrivyClient

type PrivyClient struct {
	baseUrl       string
	client        *http.Client
	privyConfig   *PrivyConfig
	authorization string
}

// Inits a new Privy Client with a custom Transport Layer service that routes https through the privyAPIVsockPort. It initates it to privysigner.PrivyCli.
func InitNewPrivyClient(portsCfg *enclave.PortConfig, awsConfig *aws.AWSConfig, environment *EnvironmentConfig) error {
	// Setup Privy Config for privy api details
	privyConfig, err := InitPrivyConfig(*awsConfig, portsCfg.AWSSecretManagerVsockPort, environment)

	if err != nil {
		log.Errorf("Could not fetch Privy config due to err: %v", err)
		return err
	}

	// Setup a new Http client for Privy API calls
	privyClient := network.InitHttpsClientWithTLSVsockTransport(portsCfg.PrivyAPIVsockPort, "api.privy.io")

	username := privyConfig.AppID
	password := privyConfig.AppSecret

	authorization := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	PrivyCli = &PrivyClient{
		baseUrl:       "https://api.privy.io",
		client:        privyClient,
		privyConfig:   privyConfig,
		authorization: authorization,
	}

	return nil
}

// Adds the standard API headers for most Privy API calls
func (cli *PrivyClient) addStandardPrivyHeaders(req *http.Request) {
	req.Header.Add("privy-app-id", cli.privyConfig.AppID)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+cli.authorization)
}

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
	signature, err := authorizationsignature.GetAuthorizationSignature(body, req.Method, cli.privyConfig.DelegatedActionsKey, url, cli.privyConfig.AppID)
	if err != nil {
		log.Errorf("Error getting authorization signature: %v", err)
		return nil, err
	}

	req.Header.Add("privy-authorization-signature", signature)

	return req, nil
}

// Simple function to get just the error message from the privy error message
func getSimplePrivyErrorMessage(responseBody []byte) string {
	var errorResp struct {
		Error string `json:"error"`
	}

	log.Infof(string(responseBody))

	err := json.Unmarshal(responseBody, &errorResp)
	if err != nil {
		return "Unable to parse Privy Error"
	}

	return errorResp.Error // Return raw response if parsing fails
}

// A simple way to handle privy errors
func handlePrivyError(res *http.Response) *data.HttpError {
	body, err := io.ReadAll(res.Body)

	if err != nil {
		log.Errorf("Error reading body: %v", err)
		return &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	errorMessage := getSimplePrivyErrorMessage(body)

	return &data.HttpError{
		Code: res.StatusCode,
		Message: data.Message{
			Message: errorMessage,
		},
	}
}

// Helper function to create internal server error
func (cli *PrivyClient) createInternalServerError() *data.HttpError {
	return &data.HttpError{
		Code: 500,
		Message: data.Message{
			Message: "Internal Server Error",
		},
	}
}

// Generic function to handle HTTP requests and responses for signing requests
func (cli *PrivyClient) executeSigningRequest(txRequest interface{}, walletId string, response interface{}) *data.HttpError {
	req, err := cli.prepSigningTxRequest(txRequest, walletId)
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

// Gets a user given a Privy userID
func (cli *PrivyClient) GetUser(userId string) (*data.PrivyUser, *data.HttpError) {
	url := fmt.Sprintf("%s%s", cli.baseUrl, GET_USER_PATH.Build(userId))

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

	return &user, nil
}
