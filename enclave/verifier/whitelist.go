package verifier

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/getaxal/verified-signer/enclave"
	log "github.com/sirupsen/logrus"
)

type WhiteList struct {
	addressList map[common.Address]bool
}

// Initiates the Whitelist for Pools and contract addresses
func InitWhitelistFromConfig(cfg *enclave.WhiteListConfig) *WhiteList {
	set := make(map[common.Address]bool)
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
	addressFormatted, err := SafeHexToAddress(address)
	if err != nil {
		log.Errorf("Invalid address:%s, will not be added to whitelist", address)
		return
	}
	(wl.addressList)[addressFormatted] = true
}

// Returns if the address specified is in the whitelist
func (wl *WhiteList) IsWhitelisted(address common.Address) bool {
	return (wl.addressList)[address]
}

// Returns if the address specified is in the whitelist
func (wl *WhiteList) IsWhitelistedString(address string) bool {
	addressFormatted, err := SafeHexToAddress(address)
	if err != nil {
		return false
	}
	return wl.IsWhitelisted(addressFormatted)
}

func SafeHexToAddress(address string) (common.Address, error) {
	addr := common.HexToAddress(address)
	if addr == common.HexToAddress("0x0") {
		return common.Address{}, fmt.Errorf("invalid hex address: %s", address)
	}

	return addr, nil
}
