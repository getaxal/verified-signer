package privysigner

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// AxalSign recreates the secp256k1_sign method in Privy but with Axals own private key
func (cli *PrivyClient) SignHashAxal(signReq *data.EthSecp256k1SignRequest) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	hashHex := signReq.Params.Hash
	// Remove 0x prefix from inputs if present
	if len(hashHex) > 2 && hashHex[:2] == "0x" {
		hashHex = hashHex[2:]
	}

	// Convert hash hex string to bytes
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		log.Errorf("failed to decode hash: %v", err)
		return nil, cli.createInternalServerError()
	}

	// Convert private key hex to ECDSA private key
	privateKey, err := crypto.HexToECDSA(cli.teeConfig.Axal.AxalClaimingWalletPK)
	if err != nil {
		log.Errorf("failed to parse private key: %v", err)
		return nil, cli.createInternalServerError()
	}

	// Sign the hash
	signature, err := crypto.Sign(hashBytes, privateKey)
	if err != nil {
		log.Errorf("failed to sign hash: %v", err)
		return nil, cli.createInternalServerError()
	}

	// Return structured response
	return &data.EthSecp256k1SignResponse{
		Method: "axal_sign",
		Data: data.EthSecp256k1SignResponseData{
			Signature: fmt.Sprintf("0x%x", signature),
			Encoding:  "hex",
		},
	}, nil
}
