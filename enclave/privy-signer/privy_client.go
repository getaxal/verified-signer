package privysigner

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/jellydator/ttlcache/v3"

	"github.com/getaxal/verified-signer/common/network"

	log "github.com/sirupsen/logrus"
)

var PrivyCli *PrivyClient

type PrivyClient struct {
	Environment   string
	baseUrl       string
	client        *http.Client
	teeConfig     *enclave.TEEConfig
	authorization string
	userCache     *ttlcache.Cache[string, data.PrivyUser]
}

// Inits a new Privy Client with a custom Transport Layer service that routes https through the privyAPIVsockPort. It initates it to privysigner.PrivyCli.
func InitNewPrivyClient(configPath string, cfg *enclave.TEEConfig) error {
	// Setup Privy Config for privy api details
	log.Infof("Setting up privy cfg in %s env", cfg.GetEnv())
	privyConfig, err := InitPrivyConfig(configPath, cfg.Ports.AWSSecretManagerVsockPort, cfg.Ports.Ec2CredsVsockPort, cfg.GetEnv())

	if err != nil {
		log.Errorf("Could not fetch Privy config due to err: %v", err)
		return err
	}

	// Setup a new Http client for Privy API calls
	privyClient := network.InitHttpsClientWithTLSVsockTransport(cfg.Ports.PrivyAPIVsockPort, "api.privy.io")

	username := privyConfig.AppID
	password := privyConfig.AppSecret

	authorization := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	cache := ttlcache.New(
		ttlcache.WithTTL[string, data.PrivyUser](30*time.Minute),
		ttlcache.WithCapacity[string, data.PrivyUser](1000),
	)

	PrivyCli = &PrivyClient{
		Environment:   cfg.GetEnv(),
		baseUrl:       "https://api.privy.io",
		client:        privyClient,
		teeConfig:     cfg,
		authorization: authorization,
		userCache:     cache,
	}

	return nil
}

// Adds the standard API headers for most Privy API calls
func (cli *PrivyClient) addStandardPrivyHeaders(req *http.Request) {
	req.Header.Add("privy-app-id", cli.teeConfig.Privy.AppID)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+cli.authorization)
}

// Simple function to get just the error message from the privy error message
func getSimplePrivyErrorMessage(responseBody []byte) string {
	var errorResp struct {
		Error string `json:"error"`
	}

	log.Infof("err: %s", string(responseBody))

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
