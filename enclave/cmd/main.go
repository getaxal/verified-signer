package main

import (
	"time"
	enclave "verified-signer-enclave"
	privysigner "verified-signer-enclave/privy-signer"
	"verified-signer-enclave/privy-signer/data"

	"github.com/axal/verified-signer-common/aws"
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

	privyCli, err := privysigner.InitNewPrivyClient(PortsConfig, AWSConfig, "prod")

	if err != nil {
		log.Fatalf("Error creating privy cli: %v", err)
	}

	////////////
	// Try it //
	////////////

	dummy_tx := data.NewSignTransactionRequest(
		&data.EthTransaction{
			To:                   "0xtest",
			ChainID:              enclave.ToInt64Ptr(1),
			Nonce:                enclave.ToInt64Ptr(1),
			Value:                enclave.ToInt64Ptr(1),
			Data:                 "0x",
			GasLimit:             enclave.ToInt64Ptr(1),
			MaxFeePerGas:         enclave.ToInt64Ptr(1),
			MaxPriorityFeePerGas: enclave.ToInt64Ptr(1),
		},
	)

	user, err := privyCli.GetUser("cmaxahxt300afjl0miaf9pcdp")

	log.Infof("user: %+v", user)
	if err != nil {
		log.Errorf("Error fetching user: %s", err)
	}

	// log.Infof("User: %+v", user)
	wallet_id := user.LinkedAccounts[1].WalletID
	err = privyCli.EthSignTransaction(dummy_tx, wallet_id)

	if err != nil {
		log.Errorf("Error signing tx: %v", err)
		return
	}

	for {
		time.Sleep(time.Minute)
	}
}
