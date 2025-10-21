package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles the Ethereum secp256k1_sign method for users. JWT auth only.
// It fetches the users delegated eth wallet from the privy backend.
func EthSecp256k1SignTxHandler(c *gin.Context) {
	auth := c.GetHeader("auth")

	if auth == "" {
		log.Errorf("Eth transaction secp256k1 sign API error: missing auth")
		resp := data.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var secp256k1Sign data.EthSecp256k1SignRequest
	err := c.ShouldBindJSON(&secp256k1Sign)

	if err != nil {
		log.Errorf("User eth secp256k1 sign API error tx data is invalid, sign req: %+v", secp256k1Sign)
		resp := data.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = secp256k1Sign.ValidateTxRequest()
	if err != nil {
		log.Errorf("User eth secp256k1 sign API error tx data is invalid with err: %v", err)
		resp := data.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// User handler - JWT auth only, no signing_type needed in request body
	resp, httpErr := privysigner.PrivyCli.EthSecp256k1Sign(&secp256k1Sign, auth, data.UserInitiatedSigning)
	if httpErr != nil {
		log.Errorf("User eth secp256k1 sign API error could not sign tx with err: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Axal handler - JWT + HMAC auth
func AxalEthSecp256k1SignTxHandler(c *gin.Context) {
	auth := c.GetHeader("auth")
	if auth == "" {
		log.Errorf("Axal eth secp256k1 sign API error: missing auth")
		resp := data.Message{Message: "Unauthorized user"}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	if auth == "" {
		log.Errorf("Axal eth transaction secp256k1 sign API error: missing auth")
		resp := data.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var secp256k1Sign data.EthSecp256k1SignRequest
	err := c.ShouldBindJSON(&secp256k1Sign)
	if err != nil {
		log.Errorf("Axal eth secp256k1 sign API error: invalid request data: %+v", secp256k1Sign)
		resp := data.Message{Message: "tx data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = secp256k1Sign.ValidateTxRequest()
	if err != nil {
		log.Errorf("Axal eth secp256k1 sign API error: validation failed: %v", err)
		resp := data.Message{Message: "tx data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// Axal handler forces signing type to "axal" and requires HMAC signature
	resp, httpErr := privysigner.PrivyCli.EthSecp256k1Sign(&secp256k1Sign, auth, data.AxalInitiatedSigning)
	if httpErr != nil {
		log.Errorf("Axal eth secp256k1 sign API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
