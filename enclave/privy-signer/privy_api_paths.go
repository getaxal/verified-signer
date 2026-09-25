package privysigner

import "fmt"

type Path string

const (
	GET_USER_PATH      Path = "/v1/users/%s"
	SIGN_TX_PATH       Path = "/v1/wallets/%s/rpc"
	CREATE_WALLET_PATH Path = "/v1/users/%s/wallets"
	GET_WALLET_PATH    Path = "/v1/wallets/%s"

	// Mints a wallet per call, for an owner named in the body. CREATE_WALLET_PATH above only
	// provisions the embedded wallet a user does not yet have, so it cannot add a second one.
	CREATE_OWNED_WALLET_PATH Path = "/v1/wallets"

	// Resolves an address to a wallet. A POST, despite being a read: the address travels in
	// the body rather than the path.
	GET_WALLET_BY_ADDRESS_PATH Path = "/v1/wallets/address"
)

func (p Path) Build(args ...interface{}) string {
	return fmt.Sprintf(string(p), args...)
}
