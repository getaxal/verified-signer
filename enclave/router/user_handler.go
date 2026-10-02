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

// Provisions an additional delegated eth wallet for the authenticated user and returns it.
//
// Identified by purpose rather than HD index: Privy's server API treats wallet_index as
// read-only, so an index in the request would name something we cannot pin. Repeat calls
// for the same purpose return the wallet the user already has.
func CreateUserWalletHandler(c *gin.Context) {
	auth := c.GetHeader("auth") // auth for this request is privy jwt

	if auth == "" {
		log.Errorf("Create user wallet API error: missing auth")
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

	var walletReq privydata.CreateUserWalletRequest
	if err := c.ShouldBindJSON(&walletReq); err != nil {
		log.Errorf("Create user wallet API error: invalid request data")
		c.JSON(http.StatusBadRequest, privydata.Message{Message: "wallet request is invalid"})
		return
	}

	if err := walletReq.Validate(); err != nil {
		log.Errorf("Create user wallet API validation failed: %v", err)
		c.JSON(http.StatusBadRequest, privydata.Message{Message: "wallet request is invalid"})
		return
	}

	wallet, httpErr := privysigner.PrivyCli.CreateUserWallet(privyId, walletReq.Purpose)
	if httpErr != nil {
		log.Errorf("Create user wallet API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, wallet)
}
