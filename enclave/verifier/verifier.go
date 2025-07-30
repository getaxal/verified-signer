package verifier

import (
	"fmt"

	"github.com/getaxal/verified-signer/enclave"
	data "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

type Verifier struct {
	verifiedAddresses *WhiteList
}

// Init a new verifier
func InitVerifieFromVerifierConfig(cfgPath string) (*Verifier, error) {
	cfg, err := enclave.LoadVerifierConfig(cfgPath)

	if err != nil {
		log.Errorf("Unable to load config from %s", cfgPath)
		return nil, fmt.Errorf("Unable to init verifier")
	}

	return &Verifier{
		verifiedAddresses: InitWhitelistFromConfig(&cfg.Whitelist),
	}, nil
}

func (v *Verifier) VerifyEthTxRequest(req data.EthTxRequest) bool {
	switch req.GetMethod() {
	case "eth_signTransaction":
		tx := req.GetTransaction()

		if tx == nil {
			return false
		}

		if !v.verifiedAddresses.IsWhitelistedString(tx.To) {
			return false
		}
		return true

	case "eth_sendTransaction":
		tx := req.GetTransaction()

		if tx == nil {
			return false
		}

		if !v.verifiedAddresses.IsWhitelistedString(tx.To) {
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
