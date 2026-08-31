package privysigner

import (
	"net/http"
	"strings"

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

	privyData := signReq.GetPrivySignData()

	// Execute privy signing directly with user request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, privyId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AxalEthPersonalSign signs a validated personal message with the user's
// delegated EVM wallet. The address check prevents a valid backend HMAC from
// accidentally signing with a different wallet.
func (cli *PrivyClient) AxalEthPersonalSign(signReq *data.AxalEthPersonalSignRequest, hmacSignature string) (*data.PersonalSignResponse, *data.HttpError) {
	if httpErr := cli.ValidateAxalPersonalSignAuth(hmacSignature, signReq); httpErr != nil {
		return nil, httpErr
	}

	user, httpErr := cli.GetUser(signReq.PrivyID)
	if httpErr != nil {
		return nil, httpErr
	}
	wallet := user.GetUsersEthDelegatedWallet()
	if wallet == nil || wallet.WalletID == "" || !strings.EqualFold(wallet.Address, signReq.WalletAddress) {
		return nil, &data.HttpError{
			Code:    http.StatusBadRequest,
			Message: data.Message{Message: "requested wallet is not the user's delegated EVM wallet"},
		}
	}

	var resp data.PersonalSignResponse
	if err := cli.executePrivySigningRequestForWallet(signReq.GetPrivySignData(), wallet.WalletID, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal signing - HMAC auth only, privy_id from request body
func (cli *PrivyClient) AxalEthSecp256k1Sign(signReq *data.AxalEthSecp256k1SignRequest, hmacSignature string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// Validate HMAC and get privy_id from request
	httpErr := cli.ValidateAxalAuthForSigningRequest(hmacSignature, signReq.Params.Hash, signReq.PrivyID)
	if httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	privyData := signReq.GetPrivySignData()

	// Execute privy signing directly with axal request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, signReq.PrivyID, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
