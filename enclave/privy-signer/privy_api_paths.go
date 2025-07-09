package privysigner

import "fmt"

type Path string

const (
	GET_USER_PATH      Path = "/v1/users/%s"
	SIGN_TX_PATH       Path = "/v1/wallets/%s/rpc"
	CREATE_WALLET_PATH Path = "/v1/users/%s/wallets"
)

func (p Path) Build(args ...interface{}) string {
	return fmt.Sprintf(string(p), args...)
}
