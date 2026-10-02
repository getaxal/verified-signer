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

// For axal signing requests - HMAC validation only.
//
// The preimage covers the wallet as well as the hash and the user, so the wallet the
// request names is authenticated rather than merely asserted.
func (cli *PrivyClient) ValidateAxalAuthForSigningRequest(hmacSignature string, req *data.AxalEthSecp256k1SignRequest) *data.HttpError {
	// Validate HMAC signature
	verified := auth.VerifyAxalSignature(req.AuthPayload(), hmacSignature, cli.teeConfig.Axal.AxalRequestSecretKey)
	if !verified {
		log.Errorf("invalid HMAC signature for payload hash: %s", req.Params.Hash)
		httpErr := &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User - Invalid HMAC",
			},
		}
		return httpErr
	}
	// No need to return privy_id as it is already validated in the request body and backend
	return nil
}

func (cli *PrivyClient) ValidateAxalPersonalSignAuth(hmacSignature string, req *data.AxalEthPersonalSignRequest) *data.HttpError {
	if !auth.VerifyAxalSignature(req.AuthPayload(), hmacSignature, cli.teeConfig.Axal.AxalRequestSecretKey) {
		return &data.HttpError{
			Code:    401,
			Message: data.Message{Message: "Unauthorized User - Invalid HMAC"},
		}
	}
	return nil
}
