package main

import (
	privysigner "github.com/axal/verified-signer/enclave/privy-signer"

	"github.com/axal/verified-signer/enclave/router"

	"github.com/axal/verified-signer/enclave"

	"github.com/axal/verified-signer/common/aws"
	log "github.com/sirupsen/logrus"
)

var AWSConfig *aws.AWSConfig
var PortsConfig *enclave.PortConfig

func main() {
	log.Info("Initiating enclave for Axal Verified Signer")

	awsCfg, err := aws.NewAWSConfigFromYAML("config.yaml")

	if err != nil {
		log.Errorf("Could not fetch AWS config due to err: %v", err)
		return
	}

	AWSConfig = awsCfg

	// Setup network port management config
	portCfg, err := enclave.LoadPortConfig("config.yaml")

	if err != nil {
		log.Errorf("Could not fetch Port config due to err: %v", err)
		return
	}

	PortsConfig = portCfg

	_, err = privysigner.InitNewPrivyClient(PortsConfig, AWSConfig, "prod")

	if err != nil {
		log.Fatalf("Error creating privy cli: %v", err)
	}

	router.InitRouter(PortsConfig.RouterVsockPort)
}
