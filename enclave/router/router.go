package router

import (
	"net/http"

	"github.com/getaxal/verified-signer/common/vsock"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func InitRouter(routerVsockPort uint32) {
	// Initialize Gin router
	r := gin.Default()

	// Init routes
	initRoutes(r)

	// Create vsock listener
	listener, err := vsock.Listen(routerVsockPort, &vsock.Config{})
	if err != nil {
		log.Panicf("Error creating vsock listener with error: %v", err)
	}

	defer listener.Close()

	log.Infof("TEE server listening on vsock port:%d", routerVsockPort)

	// Serve HTTP over vsock
	if err := http.Serve(listener, r); err != nil {
		log.Panicf("Error with starting http server with error: %v", err)
	}
}

// Initiate the API routes here
func initRoutes(r *gin.Engine) {
	v1 := r.Group("/api/v1")
	{
		// APIs for privy signing
		signerGroup := v1.Group("/signer")
		{
			ethGroup := signerGroup.Group("/eth")
			{
				ethGroup.POST("/ethSignTx/:userId", EthTransactionSignTxHandler)
				ethGroup.POST("/ethSendTx/:userId", EthTransactionSendTxHandler)
				ethGroup.POST("/personalSign/:userId", EthPersonalSignTxHandler)
			}
		}

		//APIs for getting TEE attestation
		attestationGroup := v1.Group("/attest")
		{
			attestationGroup.GET("/bytes/:nonce", GetAttestationDocHandler)
			attestationGroup.GET("/doc/:nonce", GetAttestationDocHandler)
		}

		healthGroup := v1.Group("/health")
		{
			healthGroup.GET("/ping", PingCheckHandler)
		}
	}
}
