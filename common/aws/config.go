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
	AccessKey    string `yaml:"access_key" json:"access_key"`
	AccessSecret string `yaml:"access_secret" json:"access_secret"`
}

func NewAWSConfigFromYAML(configPath string) (*AWSConfig, error) {
	var config AWSConfig

	// Load configuration using configor
	if err := configor.Load(&config, configPath); err != nil {
		log.Errorf("failed to load config from %s: %v", configPath, err)
		return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	// Validate credentials
	if config.AWSCredentials.AccessKey == "" || config.AWSCredentials.AccessSecret == "" {
		log.Errorf("could not fetch aws credentials from config file at :%s", configPath)
		return nil, fmt.Errorf("could not fetch aws credentials from config file at :%s", configPath)
	}

	return &config, nil
}
