package verifier

import (
	"github.com/getaxal/verified-signer/enclave"
	log "github.com/sirupsen/logrus"
)

type WhiteList struct {
	addressList map[string]bool
}

// Initiates the Whitelist for Pools and contract addresses
func InitWhitelistFromConfig(cfg *enclave.WhiteListConfig) *WhiteList {
	set := make(map[string]bool)
	wl := &WhiteList{
		addressList: set,
	}

	for _, pool := range cfg.Pools {
		wl.addToWhiteList(pool)
	}

	log.Infof("Initiated whitelist with %d pools", len(wl.addressList))

	return wl
}

// Adds an address to the whitelist
func (wl *WhiteList) addToWhiteList(address string) {
	(wl.addressList)[address] = true
}

// Adds an address from the whitelist
func (wl *WhiteList) removeFromWhiteList(address string) {
	(wl.addressList)[address] = false
}

// Returns if the address specified is in the whitelist
func (wl *WhiteList) IsWhitelisted(address string) bool {
	return (wl.addressList)[address]
}
