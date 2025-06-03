package main

import (
	"flag"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"

	"github.com/getaxal/verified-signer/enclave/router"

	"github.com/getaxal/verified-signer/enclave"

	"github.com/getaxal/verified-signer/common/aws"
	log "github.com/sirupsen/logrus"
)

var AWSConfig *aws.AWSConfig
var PortsConfig *enclave.PortConfig

func main() {
	log.Info("Initiating enclave for Axal Verified Signer")

	// Define command line flag for config path
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	awsCfg, err := aws.NewAWSConfigFromYAML(*configPath)

	if err != nil {
		log.Errorf("Could not fetch AWS config due to err: %v", err)
		return
	}

	AWSConfig = awsCfg

	// Setup network port management config
	portCfg, err := enclave.LoadPortConfig(*configPath)

	if err != nil {
		log.Errorf("Could not fetch Port config due to err: %v", err)
		return
	}

	PortsConfig = portCfg

	err = privysigner.InitNewPrivyClient(PortsConfig, AWSConfig, "prod")

	if err != nil {
		log.Fatalf("Error creating privy cli: %v", err)
	}

	router.InitRouter(PortsConfig.RouterVsockPort)
}
