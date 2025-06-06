package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

// Signs a transaction using the Solana signTransaction  method
func (cli *PrivyClient) SolSignTransaction(txRequest *data.SolSignTransactionRequest, walletId string) (*data.SolSignTransactionResponse, *data.HttpError) {
	var resp data.SolSignTransactionResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Signs and sends a transaction using the Solana signAndSendTransaction method
func (cli *PrivyClient) SolSignAndSendTransaction(txRequest *data.SolSignAndSendTransactionRequest, walletId string) (*data.SolSignAndSendTransactionResponse, *data.HttpError) {
	var resp data.SolSignAndSendTransactionResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Signs a transaction using the sol signMessage method
func (cli *PrivyClient) SolSignMessage(txRequest *data.SolSignMessageRequest, walletId string) (*data.SolSignMessageResponse, *data.HttpError) {
	var resp data.SolSignMessageResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
