package main

import (
	"context"
	"time"

	"github.com/getaxal/verified-signer/common/aws"
	"github.com/getaxal/verified-signer/host/network"
	log "github.com/sirupsen/logrus"
)

func main() {
	ctx := context.Background()
	log.Info("Starting Verified signer host service")

	// Proxy for Vsock to TCP for aws secret manager
	go network.InitVsockToTcpProxy(ctx, 50001, 443, "https://secretsmanager."+aws.USEast2.String()+".amazonaws.com")
	// Proxy for Vsock to TCP for privy APIs
	go network.InitVsockToTcpProxy(ctx, 50002, 443, "https://api.privy.io")
	// Proxy for TCP to Vsock for Backend to reach the enclave
	go network.InitTcpToVsockProxy(ctx, 8080, 50003)

	go network.InitVsockToTcpProxy(ctx, 50004, 80, "http://169.254.169.254")

	for {
		time.Sleep(time.Hour)
	}

}
