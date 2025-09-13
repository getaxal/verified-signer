package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

// Signs a transaction using the eth secp256_k1 method
func (cli *PrivyClient) EthSecp256k1Sign(txRequest *data.EthSecp256k1SignRequest, walletId string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	var resp data.EthSecp256k1SignResponse
	if err := cli.executeSigningRequest(*txRequest, walletId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
