package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles fetching user details from the privy backend including linked accounts.
func GetUserHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Get user request error missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.GetUser(privyUserId)

	if httpErr != nil {
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles fetching users delegated eth wallet
func GetDelegatedEthWalletHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Get user request error missing user id")
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

	ethWallet := user.GetUsersEthDelegatedWallet()
	if ethWallet == nil || ethWallet.WalletID == "" {
		log.Errorf("Get users delegated eth wallet error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated eth wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	c.JSON(http.StatusOK, ethWallet)
}

// Handles fetching users delegated sol wallet
func GetDelegatedSolWalletHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Get user request error missing user id")
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

	solWallet := user.GetUsersSolDelegatedWallet()
	if solWallet == nil || solWallet.WalletID == "" {
		log.Errorf("Get users delegated sol wallet error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated sol wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	c.JSON(http.StatusOK, solWallet)
}
