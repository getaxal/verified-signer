package verifier

type WhiteList struct {
	addressList map[string]bool
}

// Initiates the Whitelist for Pools and contract addresses
func InitWhitelist() *WhiteList {
	set := make(map[string]bool)
	return &WhiteList{
		addressList: set,
	}
}

// Adds an address to the whitelist
func (wl *WhiteList) AddToWhiteList(address string) {
	(wl.addressList)[address] = true
}

// Adds an address from the whitelist
func (wl *WhiteList) RemoveFromWhiteList(address string) {
	(wl.addressList)[address] = false
}

// Returns if the address specified is in the whitelist
func (wl *WhiteList) IsWhitelisted(address string) bool {
	return (wl.addressList)[address]
}
