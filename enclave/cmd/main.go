package main

import (
	privysigner "verified-signer-enclave/privy-signer"

	"github.com/axal/verified-signer-common/aws"
	log "github.com/sirupsen/logrus"
)

var AWSConfig *aws.AWSConfig
var PrivyConfig *privysigner.PrivyConfig

func main() {
	log.Info("Initiating enclave for Axal Verified Signer")

	awsCfg, err := aws.NewAWSConfigFromYAML("config.yaml")

	if err != nil {
		log.Errorf("Could not fetch AWS config due to err: %v", err)
		return
	}

	AWSConfig = awsCfg

	privyConfig, err := privysigner.InitPrivyConfig(*AWSConfig)

	if err != nil {
		log.Errorf("Could not fetch Privy config due to err: %v", err)
		return
	}

	PrivyConfig = privyConfig

}
