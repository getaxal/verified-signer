package main

import (
	"flag"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"

	"github.com/getaxal/verified-signer/enclave/router"

	"github.com/getaxal/verified-signer/enclave"

	log "github.com/sirupsen/logrus"
)

var PortsConfig *enclave.PortConfig

func main() {
	log.Info("Initiating enclave for Axal Verified Signer")

	// Define command line flag for config path
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Setup network port management config
	portCfg, err := enclave.LoadPortConfig(*configPath)

	if err != nil {
		log.Errorf("Could not fetch Port config due to err: %v", err)
		return
	}

	PortsConfig = portCfg

	envCfg, err := enclave.LoadEnvConfig(*configPath)

	if err != nil {
		log.Errorf("Could not fetch Env config due to err: %v", err)
		return
	}

	err = privysigner.InitNewPrivyClient(*configPath, PortsConfig, envCfg)

	if err != nil {
		log.Fatalf("Error creating privy cli: %v", err)
	}

	router.InitRouter(PortsConfig.RouterVsockPort)
}
