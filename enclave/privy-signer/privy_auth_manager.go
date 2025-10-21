package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/auth"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// For signing requests we need to check wether a transaction is a user transaction or a axal transaction. based on which one it is we have different auth processes.
func (cli *PrivyClient) ValidateAuthForSigningRequest(authString, hmacSignature, signingType string, signReq *data.EthSecp256k1SignRequest) (string, *data.HttpError) {
	switch signingType {
	// For user signing requests we will use privy jwt
	case "user":
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

	// For axal signing requests we will use JWT + HMAC signature
	case "axal":
		// First validate JWT
		privyId, err := auth.ValidateJWTAndExtractPrivyID(authString, cli.teeConfig)
		if err != nil {
			log.Errorf("invalid privy jwt: %s with err: %v", authString, err)
			httpErr := &data.HttpError{
				Code: 401,
				Message: data.Message{
					Message: "Unauthorized User - Invalid JWT",
				},
			}
			return "", httpErr
		}

		// Then validate HMAC signature
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

		return privyId, nil
	default:
		log.Errorf("invalid signing type: %s", signingType)
		httpErr := &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User",
			},
		}
		return "", httpErr
	}
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
