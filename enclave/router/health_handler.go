package router

import (
	"net/http"

	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
)

// Handler for a simple Ping health check
func PingCheckHandler(c *gin.Context) {
	resp := privydata.Message{
		Message: "pong from tee",
	}

	c.JSON(http.StatusOK, resp)
}
