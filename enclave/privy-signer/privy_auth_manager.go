package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/auth"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// For user signing requests - JWT validation only
func (cli *PrivyClient) ValidateUserAuthForSigningRequest(authString string) (string, *data.HttpError) {
	privyId, err := auth.ValidateJWTAndExtractPrivyID(authString, cli.teeConfig)
	if err != nil {
		log.Errorf("invalid privy jwt: %s with err: %v", authString, err)
		httpErr := &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User",
			},
		}
		return "", httpErr
	}
	return privyId, nil
}

// For axal signing requests - HMAC validation only
func (cli *PrivyClient) ValidateAxalAuthForSigningRequest(hmacSignature string, signReq *data.AxalEthSecp256k1SignRequest) (string, *data.HttpError) {
	// Validate HMAC signature
	verified := auth.VerifyAxalSignature(signReq.Params.Hash, hmacSignature, cli.teeConfig.Axal.AxalRequestSecretKey)
	if !verified {
		log.Errorf("invalid HMAC signature for payload: %s", signReq.Params.Hash)
		httpErr := &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User - Invalid HMAC",
			},
		}
		return "", httpErr
	}

	// Return privy_id from request body (backend already authenticated the user)
	return signReq.PrivyID, nil
}

// For Get User requests, it is always not a axal request but a user request so we simply extract the privy id
func (cli *PrivyClient) ValidateAuthForGetUserRequest(authString string) (string, *data.HttpError) {
	privyId, err := auth.ValidateJWTAndExtractPrivyID(authString, cli.teeConfig)
	log.Errorf("invalid privy jwt: %s with err: %v", authString, err)
	if err != nil {
		httpErr := &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User",
			},
		}
		return "", httpErr
	}

	return privyId, nil
}
