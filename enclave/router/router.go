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
		// User routes for user initiated signing
		userGroup := v1.Group("/user")
		{
			userGroup.GET("", GetUserHandler)

			signerGroup := v1.Group("/signer")
			{
				ethGroup := signerGroup.Group("/eth")
				{
					ethGroup.POST("/secp256k1Sign", UserEthSecp256k1SignTxHandler)
				}
			}

		}

		// Axal routes for axal initiated signing
		axalGroup := v1.Group("/axal")
		{
			axalSignerGroup := axalGroup.Group("/signer")
			{
				axalEthGroup := axalSignerGroup.Group("/eth")
				{
					axalEthGroup.POST("/secp256k1Sign", AxalEthSecp256k1SignTxHandler)
				}
			}
		}

		//APIs for getting TEE attestation
		attestationGroup := v1.Group("/attest")
		{
			attestationGroup.GET("/bytes/:nonce", GetAttestationBytesHandler)
			attestationGroup.GET("/doc/:nonce", GetAttestationDocHandler)
		}

		healthGroup := v1.Group("/health")
		{
			healthGroup.GET("/ping", PingCheckHandler)
		}
	}
}
