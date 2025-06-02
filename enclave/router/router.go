package router

import (
	"net/http"

	"github.com/axal/verified-signer/common/vsock"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func InitRouter(routerVsockPort uint32) {
	// Initialize Gin router
	r := gin.Default()

	// Init routes
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong from tee",
		})
	})

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
