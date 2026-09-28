package privysigner

import "fmt"

type Path string

const (
	GET_USER_PATH      Path = "/v1/users/%s"
	SIGN_TX_PATH       Path = "/v1/wallets/%s/rpc"
	CREATE_WALLET_PATH Path = "/v1/users/%s/wallets"
	GET_WALLET_PATH    Path = "/v1/wallets/%s"

	// The wallets collection. POSTed to, to mint a wallet per call for an owner named in the
	// body — CREATE_WALLET_PATH above only provisions the embedded wallet a user does not yet
	// have, so it cannot add a second one. GET with a user_id filter lists the wallets Privy
	// considers that user's, which is the authoritative answer to whether a wallet is theirs.
	WALLETS_PATH Path = "/v1/wallets"
)

func (p Path) Build(args ...interface{}) string {
	return fmt.Sprintf(string(p), args...)
}
