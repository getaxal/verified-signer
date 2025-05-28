package privysigner

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	enclave "verified-signer-enclave"
	"verified-signer-enclave/network"

	"github.com/axal/verified-signer-common/aws"

	log "github.com/sirupsen/logrus"
)

type PrivyClient struct {
	baseUrl     string
	client      *http.Client
	privyConfig *PrivyConfig
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

	return &PrivyClient{
		baseUrl:     "https://api.privy.io",
		client:      privyClient,
		privyConfig: privyConfig,
	}, nil

}

// Gets a user given a userID from the Privy Backend
func (cli *PrivyClient) GetUser(userId string) error {
	path := "/v1/users/"
	url := fmt.Sprintf("%s%s%s", cli.baseUrl, path, userId)

	username := cli.privyConfig.AppID
	password := cli.privyConfig.AppSecret

	authorization := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(authorization))

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return err
	}

	// Add headers
	req.Header.Add("privy-app-id", cli.privyConfig.AppID)
	req.Header.Add("Authorization", "Basic "+encoded)
	req.Header.Add("Content-Type", "application/json")

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return err
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
		return err
	}

	// Print results
	log.Infof("Status: %s\n", res.Status)
	log.Infof("Headers: %v\n", res.Header)
	log.Infof("Response Body:\n%s\n", string(body))
	return nil
}
