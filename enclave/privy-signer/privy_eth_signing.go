package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// User signing - JWT auth only, privy_id extracted from JWT
func (cli *PrivyClient) UserEthSecp256k1Sign(signReq *data.UserEthSecp256k1SignRequest, authString string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// Validate JWT and get privy_id
	privyId, httpErr := cli.ValidateUserAuthForSigningRequest(authString)
	if httpErr != nil {
		log.Errorf("invalid user auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	// Execute privy signing directly with user request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(*signReq, privyId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal signing - HMAC auth only, privy_id from request body
func (cli *PrivyClient) AxalEthSecp256k1Sign(signReq *data.UserEthSecp256k1SignRequest, privyID string, hmacSignature string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// Validate HMAC and get privy_id from request
	httpErr := cli.ValidateAxalAuthForSigningRequest(hmacSignature, signReq.Params.Hash)
	if httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	// Execute privy signing directly with axal request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(*signReq, privyID, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
