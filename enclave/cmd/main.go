package main

import (
	"flag"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"

	"github.com/getaxal/verified-signer/enclave/router"

	"github.com/getaxal/verified-signer/enclave"

	log "github.com/sirupsen/logrus"
)

var TeeCfg *enclave.TEEConfig

func main() {
	log.Info("Initiating enclave for Axal Verified Signer")

	// Define command line flag for config path
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Setup network port management config
	teeCfg, err := enclave.LoadTEEConfig(*configPath)

	if err != nil {
		log.Fatalf("Could not fetch TEE config due to err: %v", err)
	}

	TeeCfg = teeCfg

	err = privysigner.InitNewPrivyClient(*configPath, teeCfg)

	if err != nil {
		log.Fatalf("Error creating privy cli: %v", err)
	}

	router.InitRouter(TeeCfg.Ports.RouterVsockPort)
}
