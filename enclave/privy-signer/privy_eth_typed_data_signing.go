package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// User EIP-712 typed data signing - JWT auth only, privy_id extracted from JWT.
// The typed data is hashed in-enclave; the digest is signed via the existing
// secp256k1_sign privy path.
func (cli *PrivyClient) UserEthSignTypedData(signReq *data.UserEthSignTypedDataRequest, authString string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	privyId, httpErr := cli.ValidateUserAuthForSigningRequest(authString)
	if httpErr != nil {
		log.Errorf("invalid user auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	logTypedDataAudit(signReq.GetDomainInfo())

	privyData := signReq.GetPrivySignData()

	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, privyId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal EIP-712 typed data signing - HMAC auth over typed_data + ":" + privy_id
func (cli *PrivyClient) AxalEthSignTypedData(signReq *data.AxalEthSignTypedDataRequest, hmacSignature string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	httpErr := cli.ValidateAxalAuthForSigningRequest(hmacSignature, signReq.Params.TypedData, signReq.PrivyID)
	if httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	logTypedDataAudit(signReq.GetDomainInfo())

	privyData := signReq.GetPrivySignData()

	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, signReq.PrivyID, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// User EIP-191 personal_sign - JWT auth only. The message is hashed in-enclave.
func (cli *PrivyClient) UserEthPersonalSign(signReq *data.UserEthPersonalSignRequest, authString string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	privyId, httpErr := cli.ValidateUserAuthForSigningRequest(authString)
	if httpErr != nil {
		log.Errorf("invalid user auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	privyData := signReq.GetPrivySignData()

	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, privyId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal EIP-191 personal_sign - HMAC auth over message + ":" + privy_id
func (cli *PrivyClient) AxalEthPersonalSign(signReq *data.AxalEthPersonalSignRequest, hmacSignature string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	httpErr := cli.ValidateAxalAuthForSigningRequest(hmacSignature, signReq.Params.Message, signReq.PrivyID)
	if httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	privyData := signReq.GetPrivySignData()

	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(privyData, signReq.PrivyID, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Audit trail of what typed data domains the enclave signs for.
func logTypedDataAudit(info *data.TypedDataDomainInfo, err error) {
	if err != nil || info == nil {
		log.Warnf("typed data signing: could not extract domain info for audit log: %v", err)
		return
	}
	log.Infof("typed data signing: domain=%q verifyingContract=%s chainId=%s primaryType=%s",
		info.Name, info.VerifyingContract, info.ChainID, info.PrimaryType)
}
