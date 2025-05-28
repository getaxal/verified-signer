package main

import (
	"context"
	"verified-signer-enclave/network"

	"github.com/axal/verified-signer-common/aws"
	secretmanager "github.com/axal/verified-signer-common/aws/secret_manager"
	log "github.com/sirupsen/logrus"
)

func main() {
	println("Hello world")

	cfg, err := aws.NewAWSConfigFromYAML("config.yaml")

	if err != nil {
		log.Errorf("Cannot fetch aws config")
	}

	smCfg := secretmanager.SecretManagerConfig{
		Credentials: cfg.AWSCredentials,
		Region:      aws.USEast2,
	}

	log.Infof("Loaded secret manager config: %+v", smCfg)

	sm := secretmanager.NewSecretManager(smCfg)

	sm.Client = network.InitHttpsClientWithTLSVsockTransport(50001, "secretsmanager.us-east-2.amazonaws.com")

	res, err := sm.GetSecret(context.Background(), "privy/dev")

	if err != nil {
		log.Errorf("Could not get secret with err: %v", err)
		return
	}

	log.Infof("Secret: %+v", res)
}
