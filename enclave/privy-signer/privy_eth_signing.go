package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

// Signs a transaction using the eth_signTransaction method
func (cli *PrivyClient) EthSignTransaction(txRequest *data.EthSignTransactionRequest, walletId string) (*data.EthSignTransactionResponse, *data.HttpError) {
	var resp data.EthSignTransactionResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Signs and sends a transaction using the eth_sendTransaction method
func (cli *PrivyClient) EthSendTransaction(txRequest *data.EthSendTransactionRequest, walletId string) (*data.EthSendTransactionResponse, *data.HttpError) {
	var resp data.EthSendTransactionResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Signs a transaction using the eth personal sign method
func (cli *PrivyClient) EthPersonalSign(txRequest *data.EthPersonalSignRequest, walletId string) (*data.EthPersonalSignResponse, *data.HttpError) {
	var resp data.EthPersonalSignResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Signs a transaction using the eth secp256_k1 method
func (cli *PrivyClient) EthSecp256k1Sign(txRequest *data.EthSecp256k1SignRequest, walletId string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	var resp data.EthSecp256k1SignResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
