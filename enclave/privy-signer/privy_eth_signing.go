package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// User signing - JWT auth only, privy_id extracted from JWT.
//
// The request names the wallet to sign with, and it is resolved against the JWT's user:
// an address belonging to somebody else is not found on this user and is rejected.
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
	if err := cli.executePrivySigningRequest(privyData, privyId, signReq.WalletAddress, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AxalEthPersonalSign signs a validated personal message with the user's delegated EVM
// wallet. The wallet is named by the request, covered by the HMAC, and checked against
// the user before signing.
func (cli *PrivyClient) AxalEthPersonalSign(signReq *data.AxalEthPersonalSignRequest, hmacSignature string) (*data.PersonalSignResponse, *data.HttpError) {
	if httpErr := cli.ValidateAxalPersonalSignAuth(hmacSignature, signReq); httpErr != nil {
		return nil, httpErr
	}

	wallet, httpErr := cli.resolveDelegatedWallet(signReq.PrivyID, signReq.WalletAddress)
	if httpErr != nil {
		return nil, httpErr
	}

	var resp data.PersonalSignResponse
	if err := cli.executePrivySigningRequestForWallet(signReq.GetPrivySignData(), wallet.WalletID, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal signing - HMAC auth only, privy_id from request body
func (cli *PrivyClient) AxalEthSecp256k1Sign(signReq *data.AxalEthSecp256k1SignRequest, hmacSignature string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// Validate HMAC. The preimage covers the wallet, so the address below is authenticated.
	httpErr := cli.ValidateAxalAuthForSigningRequest(hmacSignature, signReq)
	if httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	privyData := signReq.GetPrivySignData()

	// Execute privy signing directly with axal request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, signReq.PrivyID, signReq.WalletAddress, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
