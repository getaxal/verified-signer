package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func GetUserHandler(c *gin.Context) {
	privyJwt := c.GetHeader("auth")

	if privyJwt == "" {
		log.Errorf("Get user API error: missing auth")
		resp := privydata.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	user, httpErr := privysigner.PrivyCli.GetUser(privyJwt)
	if httpErr != nil {
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, user)
}
