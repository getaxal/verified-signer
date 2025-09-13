package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles the Ethereum secp256k1_sign method. It takes the users userId as a path param and a EthSecp256k1SignResponse as the json body.
// It fetches the users delegated eth wallet from the privy backend.
func EthSecp256k1SignTxHandler(c *gin.Context) {
	privyJwt := c.GetHeader("auth")

	if privyJwt == "" {
		log.Errorf("Eth transaction secp256k1 sign API error: missing auth")
		resp := privydata.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var secp256k1Sign privydata.EthSecp256k1SignRequest
	err := c.ShouldBindJSON(&secp256k1Sign)

	if err != nil {
		log.Errorf("Eth secp256k1 sign API error tx data is invalid, sign req: %+v", secp256k1Sign)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = secp256k1Sign.ValidateTxRequest()
	if err != nil {
		log.Errorf("Eth secp256k1 sign API error tx data is invalid with err: %v", err)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	user, httpErr := privysigner.PrivyCli.GetUser(privyJwt)
	if httpErr != nil {
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	ethWallet := user.GetUsersEthDelegatedWallet()
	if ethWallet == nil || ethWallet.WalletID == "" {
		log.Errorf("Eth secp256k1 sign API error user %s does not have a delegated eth wallet", user.PrivyID)
		resp := privydata.Message{
			Message: "user does not have an delegated eth wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.EthSecp256k1Sign(&secp256k1Sign, ethWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Eth secp256k1 sign API error user %s could not sign tx with err: %v", user.PrivyID, httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
