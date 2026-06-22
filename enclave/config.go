package enclave

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/getaxal/verified-signer/common/aws"
	secretmanager "github.com/getaxal/verified-signer/common/aws/secret_manager"
	"github.com/jinzhu/configor"
	log "github.com/sirupsen/logrus"
)

type TEEConfig struct {
	Environment string      `yaml:"environment"`
	Ports       PortConfig  `yaml:"ports"`
	Axal        AxalConfig  `yaml:"axal"`
	Region      string      `yaml:"region"`
	Privy       PrivyConfig `yaml:"privy"`
}

type PortConfig struct {
	AWSSecretManagerVsockPort uint32 `yaml:"aws_secret_manager_vsock_port"`
	PrivyAPIVsockPort         uint32 `yaml:"privy_api_vsock_port"`
	RouterVsockPort           uint32 `yaml:"router_vsock_port"`
	Ec2CredsVsockPort         uint32 `yaml:"ec2_creds_vsock_port"`
	KMSVsockPort              uint32 `yaml:"kms_vsock_port"`
}

type AxalConfig struct {
	AxalRequestSecretKey string `yaml:"axal_request_secret_key" json:"axal_request_secret_key"`
}

// Config for privy access
type PrivyConfig struct {
	AppID                 string `json:"app_id" yaml:"app_id"`
	DelegatedActionsKey   string `json:"delegated_actions_key" yaml:"delegated_actions_key"`
	AppSecret             string `json:"app_secret" yaml:"app_secret"`
	JWTVerificationKey    string `json:"jwt_verification_key" yaml:"jwt_verification_key"`
	DelegatedActionsKeyId string `json:"key_id" yaml:"key_id"`
}

// Init Privy config by fetching details from AWS SecretsManager using a Vsock HTTPS client. We need to provide a Vsock port for AWS communication for
// this client.
func InitPrivyConfig(configPath string, teeConfig TEEConfig) (*PrivyConfig, error) {
	log.Infof("Loaded secret manager config")

	sm, err := secretmanager.NewSecretManager(configPath, teeConfig.Environment, teeConfig.Ports.AWSSecretManagerVsockPort, teeConfig.Ports.Ec2CredsVsockPort)
	if err != nil {
		return nil, err
	}

	log.Info("Fetching Privy config from Secret Manager")

	var secretResponse *secretmanager.GetSecretValueResponse

	switch teeConfig.Environment {
	case "prod":
		secretResponse, err = sm.GetSecret(context.Background(), "prod/privy")
	case "dev", "local":
		secretResponse, err = sm.GetSecret(context.Background(), "dev/privy")
	case "staging":
		secretResponse, err = sm.GetSecret(context.Background(), "staging/privy")
	default:
		return nil, fmt.Errorf("invalid environment, no such env: %s", teeConfig.Environment)
	}

	if err != nil {
		return nil, err
	}

	if secretResponse.SecretString == "" {
		return nil, fmt.Errorf("secret does not contain string data")
	}

	// In prod/dev/staging the stored value is a base64 KMS ciphertext that can
	// only be opened via an attestation-bound kms:Decrypt inside the enclave,
	// so the parent host cannot recover it even though it proxies the call and
	// holds the same instance-role credentials.
	plaintext, err := MaybeUnwrap(teeConfig.Environment, secretResponse.SecretString, sm.Config.Region.String(), teeConfig.Ports.KMSVsockPort, sm.Config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap privy secret: %w", err)
	}

	var config PrivyConfig
	err = json.Unmarshal(plaintext, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret as PrivyConfig: %w", err)
	}

	// Validate required fields
	if config.AppID == "" || config.AppSecret == "" || config.DelegatedActionsKey == "" || config.JWTVerificationKey == "" {
		return nil, fmt.Errorf("secret missing required fields")
	}

	return &config, nil
}

// Loads Ports config from a config path
func LoadTEEConfig(configPath string) (*TEEConfig, error) {
	log.Info("Loading port config for networking ports")

	var config TEEConfig
	if err := configor.Load(&config, configPath); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	// Incorrect cfg path triggers here for configor, it will just load empty config
	if config.Ports.AWSSecretManagerVsockPort == 0 || config.Ports.PrivyAPIVsockPort == 0 || config.Ports.RouterVsockPort == 0 {
		return nil, fmt.Errorf("no port loaded from: %s", configPath)
	}

	if config.Environment == "" {
		return nil, fmt.Errorf("no env loaded from: %s", configPath)
	}

	if config.Environment != "local" {

		if config.Ports.KMSVsockPort == 0 {
			return nil, fmt.Errorf("no kms_vsock_port loaded from: %s", configPath)
		}

		log.Info("loading axal wallets config from sm")
		if config.Region == "" {
			config.Region = aws.DEFAULT_AWS_REGION
		}

		client, err := secretmanager.NewSecretManager(configPath, config.Environment, config.Ports.AWSSecretManagerVsockPort, config.Ports.Ec2CredsVsockPort)

		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
		}

		var axalCfg *AxalConfig
		axalCfg, err = LoadCfgFromSM[AxalConfig](&config, *client, "axal")
		if err != nil {
			return nil, fmt.Errorf("failed to load axal wallets config from %s: %w", configPath, err)
		}
		config.Axal = *axalCfg

		log.Info("loaded axal wallets config from sm")
	}

	// Fail-closed guard: an empty AxalRequestSecretKey turns the HMAC check
	// in VerifyAxalSignature into a public function (HMAC with key="" is
	// reproducible by any caller). Refuse to start the enclave rather than
	// silently authorize forged signing requests.
	if config.Axal.AxalRequestSecretKey == "" {
		return nil, fmt.Errorf("axal_request_secret_key is empty after config load (env=%s); refusing to start", config.Environment)
	}

	log.Info("loading privy config")
	privyConfig, err := InitPrivyConfig(configPath, config)

	if err != nil {
		return nil, fmt.Errorf("failed to load privy config from %s: %w", configPath, err)
	}

	config.Privy = *privyConfig
	log.Info("loaded privy config")

	log.Infof("loaded tee config: %v", config)

	return &config, nil
}

func (cfg *TEEConfig) GetEnv() string {
	if cfg.Environment == "prod" || cfg.Environment == "dev" || cfg.Environment == "local" || cfg.Environment == "staging" {
		return cfg.Environment
	} else {
		return "local"
	}
}

// Generic function to load any configuration type from Secrets Manager
func LoadCfgFromSM[T any](cfg *TEEConfig, client secretmanager.SecretManager, secretType string) (*T, error) {
	var configData T

	secretName := fmt.Sprintf("%s/%s", cfg.Environment, secretType)
	secret, err := client.GetSecret(context.Background(), secretName)

	if err != nil {
		return nil, fmt.Errorf("failed to load %s cfg from secrets manager with err: %w", secretType, err)
	}

	log.Infof("Fetched Secret from secrets manager with secret name : %s", secretName)

	// Like the privy secret, non-local secrets are stored as a base64 KMS
	// ciphertext and unwrapped via attestation-bound kms:Decrypt in the enclave.
	plaintext, err := MaybeUnwrap(cfg.Environment, secret.SecretString, client.Config.Region.String(), cfg.Ports.KMSVsockPort, client.Config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap %s secret: %w", secretType, err)
	}

	// Try normal unmarshal first
	if err := json.Unmarshal(plaintext, &configData); err != nil {
		// If it's a string-to-int conversion error, try to fix it
		if strings.Contains(err.Error(), "cannot unmarshal string into Go struct field") &&
			strings.Contains(err.Error(), "of type int") {

			// Unmarshal into a map first to manipulate the data
			var rawData map[string]interface{}
			if err := json.Unmarshal(plaintext, &rawData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal %s config from secrets manager: %w", secretType, err)
			}

			// Convert string port values to integers
			for key, value := range rawData {
				if strings.Contains(key, "port") {
					if strVal, ok := value.(string); ok {
						if intVal, err := strconv.Atoi(strVal); err == nil {
							rawData[key] = intVal
						}
					}
				}
			}

			// Marshal back to JSON and unmarshal into target struct
			fixedJSON, err := json.Marshal(rawData)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal fixed %s config: %w", secretType, err)
			}

			if err := json.Unmarshal(fixedJSON, &configData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal fixed %s config from secrets manager: %w", secretType, err)
			}
		} else {
			return nil, fmt.Errorf("failed to unmarshal %s config from secrets manager: %w", secretType, err)
		}
	}

	log.Infof("Loaded config from secrets manager with secret type: %s and config data: %v", secretType, configData)

	return &configData, nil
}
