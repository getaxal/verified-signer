package privysigner

import (
	"context"
	"encoding/json"
	"fmt"
	"verified-signer-enclave/network"

	"github.com/axal/verified-signer-common/aws"
	log "github.com/sirupsen/logrus"

	secretmanager "github.com/axal/verified-signer-common/aws/secret_manager"
)

// Config for privy access
type PrivyConfig struct {
	AppID               string `json:"app_id" yaml:"app_id"`
	DelegatedActionsKey string `json:"delegated_actions_key" yaml:"delegated_actions_key"`
	AppSecret           string `json:"app_secret" yaml:"app_secret"`
	JWTVerificationKey  string `json:"jwt_verification_key" yaml:"jwt_verification_key"`
}

func InitPrivyConfig(awsConfig aws.AWSConfig) (*PrivyConfig, error) {
	smCfg := secretmanager.SecretManagerConfig{
		Credentials: awsConfig.AWSCredentials,
		Region:      aws.USEast2,
	}

	log.Infof("Loaded secret manager config")

	sm := secretmanager.NewSecretManager(smCfg)

	sm.Client = network.InitHttpsClientWithTLSVsockTransport(50001, "secretsmanager.us-east-2.amazonaws.com")

	log.Info("Fetching Privy config from Secret Manager")

	secretResponse, err := sm.GetSecret(context.Background(), "privy/dev")

	if err != nil {
		return nil, err
	}

	if secretResponse.SecretString == "" {
		return nil, fmt.Errorf("secret does not contain string data")
	}

	var config PrivyConfig
	err = json.Unmarshal([]byte(secretResponse.SecretString), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret as PrivyConfig: %w", err)
	}

	// Validate required fields
	if config.AppID == "" || config.AppSecret == "" || config.DelegatedActionsKey == "" || config.JWTVerificationKey == "" {
		return nil, fmt.Errorf("secret missing required fields")
	}

	return &config, nil
}
