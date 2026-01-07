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
func (cli *PrivyClient) ValidateAxalAuthForSigningRequest(hmacSignature, hash, privyId string) *data.HttpError {
	// Validate HMAC signature
	verified := auth.VerifyAxalSignature(hash+":"+privyId, hmacSignature, cli.teeConfig.Axal.AxalRequestSecretKey)
	if !verified {
		log.Errorf("invalid HMAC signature for payload: %s", hash)
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
