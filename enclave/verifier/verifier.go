package verifier

import (
	data "github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

type Verifier struct {
	verifiedAddresses *WhiteList
}

// Init a new verifier
func InitVerifier() *Verifier {
	return &Verifier{
		verifiedAddresses: InitWhitelist(),
	}
}

func (v *Verifier) VerifyEthTxRequest(req data.EthTxRequest) bool {
	switch req.GetMethod() {
	case "eth_signTransaction":
		tx := req.GetTransaction()
		if !v.verifiedAddresses.IsWhitelisted(tx.To) {
			return false
		}
		return true

	case "eth_sendTransaction":
		tx := req.GetTransaction()
		if !v.verifiedAddresses.IsWhitelisted(tx.To) {
			return false
		}
		return true

	case "personal_sign":
		tx := req.GetTransaction()
		if tx != nil {
			return false
		}
		return true

	default:
		return false
	}
}
