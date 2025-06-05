package enclave

import (
	"fmt"

	"github.com/jinzhu/configor"
	log "github.com/sirupsen/logrus"
)

type PortConfig struct {
	AWSSecretManagerVsockPort uint32 `yaml:"aws_secret_manager_vsock_port"`
	PrivyAPIVsockPort         uint32 `yaml:"privy_api_vsock_port"`
	RouterVsockPort           uint32 `yaml:"router_vsock_port"`
}

// Loads Ports config from a config path
func LoadPortConfig(configPath string) (*PortConfig, error) {
	log.Info("Loading port config for networking ports")

	type Config struct {
		Ports PortConfig `yaml:"ports"`
	}

	var config Config
	if err := configor.Load(&config, configPath); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	// Incorrect cfg path triggers here for configor, it will just load empty config
	if config.Ports.AWSSecretManagerVsockPort == 0 || config.Ports.PrivyAPIVsockPort == 0 || config.Ports.RouterVsockPort == 0 {
		return nil, fmt.Errorf("no port loaded from: %s", configPath)
	}

	return &config.Ports, nil
}

// Config for whitelisted pools
type WhiteListConfig struct {
	Pools []string `yaml:"whitelisted_pools"`
}

// Config for the verifier layer
type VerifierConfig struct {
	Whitelist WhiteListConfig `yaml:"whitelist_config"`
}

// Load whitelist config, must have at least one pool in the whitelist
func LoadVerifierConfig(configPath string) (*VerifierConfig, error) {
	var config VerifierConfig

	err := configor.Load(&config, configPath)
	if err != nil {
		log.Errorf("Failed to load verifier config: %v", err)
		return nil, fmt.Errorf("Failed to load verifier config")
	}
	// Incorrect cfg path triggers here for configor, it will just load empty config
	if len(config.Whitelist.Pools) == 0 {
		log.Errorf("No whitelisted pools configured")
		return nil, fmt.Errorf("Failed to load verifier config")
	}

	log.Infof("Successfully loaded %d whitelisted pools\n", len(config.Whitelist.Pools))

	return &config, nil
}
