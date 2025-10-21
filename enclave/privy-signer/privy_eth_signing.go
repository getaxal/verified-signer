package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// Signs a transaction using the eth secp256_k1 method
func (cli *PrivyClient) EthSecp256k1Sign(signReq *data.EthSecp256k1SignRequest, authString, hmacSignature, signingType string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// validate and fetch the privy id if its a user operation
	privyId, httpErr := cli.ValidateAuthForSigningRequest(authString, hmacSignature, signingType, signReq)
	if httpErr != nil {
		log.Errorf("invalid auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	switch signingType {
	// For user operations we execute a privy signing
	case "user":
		var resp data.EthSecp256k1SignResponse
		if err := cli.executePrivySigningRequest(*signReq, privyId, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	case "axal":
		var resp data.EthSecp256k1SignResponse
		if err := cli.executePrivySigningRequest(*signReq, privyId, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	default:
		log.Errorf("invalid signing type: %s", signingType)
		httpErr := &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User",
			},
		}
		return nil, httpErr
	}
}
