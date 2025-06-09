package aws

import (
	"fmt"

	"github.com/jinzhu/configor"
	log "github.com/sirupsen/logrus"
)

type AWSConfig struct {
	AWSCredentials AWSCredentials `yaml:"aws_credentials" json:"aws_credentials"`
}

// AWS Credentials for temporary
type AWSCredentials struct {
	AccessKey    string    `yaml:"access_key" json:"access_key"`
	AccessSecret string    `yaml:"access_secret" json:"access_secret"`
	SessionToken string    `yaml:"session_token,omitempty"`
	Region       AWSRegion `yaml:"region" json:"region"`
}

// Inits a new AWSConfig by parsing the config file at the given path. Supports yaml and json.
func NewAWSConfigFromYAML(configPath string) (*AWSConfig, error) {
	var config AWSConfig

	// Load configuration using configor
	if err := configor.Load(&config, configPath); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	// Validate credentials
	if config.AWSCredentials.AccessKey == "" || config.AWSCredentials.AccessSecret == "" {
		return nil, fmt.Errorf("could not fetch aws credentials from config file at :%s", configPath)
	}

	log.Infof("Loaded AWS config from: %s", configPath)

	return &config, nil
}
