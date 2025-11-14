package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func GetUserHandler(c *gin.Context) {
	auth := c.GetHeader("auth") // auth for this request is privy jwt

	if auth == "" {
		log.Errorf("Get user API error: missing auth")
		resp := privydata.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	privyId, httpErr := privysigner.PrivyCli.ValidateUserAuthForSigningRequest(auth)
	if httpErr != nil {
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	user, httpErr := privysigner.PrivyCli.GetUser(privyId)
	if httpErr != nil {
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, user)
}
