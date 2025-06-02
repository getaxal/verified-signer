package network

import (
	"context"

	vsockproxy "github.com/getaxal/verified-signer/common/vsock/proxy"

	log "github.com/sirupsen/logrus"
)

// This function listens to the Vsock port provided and forwards the traffic to the TCP port provided. it will forward all traffic from this vsock port to
// the URL provided.
func InitVsockToTcpProxy(ctx context.Context, vsockPort uint32, tcpPort uint32, forwardUrl string) {
	log.Infof("Listening to vsock at port: %v", vsockPort)
	log.Infof("Forwarding tcp to %s:%v", forwardUrl, tcpPort)
	vsockproxy.NewVsockProxy(ctx, forwardUrl, tcpPort, vsockPort)
}

// This function listens to the TCP port provided and forwards the network call into the Vsock port provided.
func InitTcpToVsockProxy(ctx context.Context, tcpPort uint32, vsockPort uint32) {
	log.Infof("Listening to tcp at port: %d", tcpPort)
	log.Infof("Forwarding to vsock at port: %d", vsockPort)

	vsockproxy.NewProxy(ctx, tcpPort, 5, vsockPort)
}
