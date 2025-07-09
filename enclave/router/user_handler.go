package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func GetUserHandler(c *gin.Context) {
	privyUserId := c.Param("userId")
	if privyUserId == "" {
		log.Errorf("Get User API error: missing privy user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	user, httpErr := privysigner.PrivyCli.GetUser(privyUserId)
	if httpErr != nil {
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, user)
}
