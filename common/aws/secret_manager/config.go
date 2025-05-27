package secretmananger

import "github.com/axal/verified-signer-common/aws"

type SecretManagerConfig struct {
	Credentials aws.AWSCredentials
	Region      aws.AWSRegion
}

func (cfg *SecretManagerConfig) GetSecretManagerEndpoint() string {
	return "https://secretsmanager." + cfg.Region.String() + ".amazonaws.com/"
}
