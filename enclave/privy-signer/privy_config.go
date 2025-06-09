package privysigner

import (
	"context"
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	secretmanager "github.com/getaxal/verified-signer/common/aws/secret_manager"
)

// Config for privy access
type PrivyConfig struct {
	AppID               string `json:"app_id" yaml:"app_id"`
	DelegatedActionsKey string `json:"delegated_actions_key" yaml:"delegated_actions_key"`
	AppSecret           string `json:"app_secret" yaml:"app_secret"`
	JWTVerificationKey  string `json:"jwt_verification_key" yaml:"jwt_verification_key"`
}

// Init Privy config by fetching details from AWS SecretsManager using a Vsock HTTPS client. We need to provide a Vsock port for AWS communication for
// this client.
func InitPrivyConfig(configPath string, awsSecretsManagerPort uint32, ec2Port uint32, environment string) (*PrivyConfig, error) {
	log.Infof("Loaded secret manager config")

	sm, err := secretmanager.NewSecretManager(configPath, environment, awsSecretsManagerPort, ec2Port)
	if err != nil {
		return nil, err
	}

	log.Info("Fetching Privy config from Secret Manager")

	var secretResponse *secretmanager.GetSecretValueResponse

	if environment == "prod" {
		secretResponse, err = sm.GetSecret(context.Background(), "prod/privy")
	} else if environment == "dev" || environment == "local" {
		secretResponse, err = sm.GetSecret(context.Background(), "dev/privy")
	} else {
		return nil, fmt.Errorf("invalid environment, no such env: %s", environment)
	}

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
