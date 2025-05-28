package enclave

import (
	"fmt"

	"github.com/jinzhu/configor"
	log "github.com/sirupsen/logrus"
)

type PortConfig struct {
	AWSSecretManagerVsockPort uint32 `yaml:"aws_secret_manager_vsock_port"`
	PrivyAPIVsockPort         uint32 `yaml:"privy_api_vsock_port"`
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

	if config.Ports.AWSSecretManagerVsockPort == 0 || config.Ports.PrivyAPIVsockPort == 0 {
		return nil, fmt.Errorf("no port loaded from: %s", configPath)
	}

	return &config.Ports, nil
}
