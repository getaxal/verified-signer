package main

import (
	"context"

	"github.com/axal/verified-signer-common/aws"
	"github.com/axal/verified-signer-host/proxy"
	log "github.com/sirupsen/logrus"
)

func main() {
	ctx := context.Background()
	log.Info("Starting google auth POC host service")

	go proxy.InitVsockToTcpProxy(ctx, 50001, 443, "https://secretsmanager."+aws.USEast2.String()+".amazonaws.com")

	for {
	}
}
