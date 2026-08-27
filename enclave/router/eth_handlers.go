package router

import (
	"net/http"
	"time"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles the Ethereum secp256k1_sign method for users. JWT auth only.
// It fetches the users delegated eth wallet from the privy backend.
func UserEthSecp256k1SignTxHandler(c *gin.Context) {
	auth := c.GetHeader("auth")

	if auth == "" {
		log.Errorf("User eth secp256k1 sign API error: missing auth")
		resp := data.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var secp256k1Sign data.UserEthSecp256k1SignRequest
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

	// User handler - JWT auth only, privy_id extracted from JWT
	resp, httpErr := privysigner.PrivyCli.UserEthSecp256k1Sign(&secp256k1Sign, auth)
	if httpErr != nil {
		log.Errorf("User eth secp256k1 sign API error could not sign tx with err: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// AxalEthPersonalSignHandler signs only validated Crossmint wallet-ownership
// challenges. Authentication is backend-to-enclave HMAC; no user JWT or client
// signing capability is accepted on this route.
func AxalEthPersonalSignHandler(c *gin.Context) {
	hmacSignature := c.GetHeader("auth")
	if hmacSignature == "" {
		c.JSON(http.StatusUnauthorized, data.Message{Message: "Missing HMAC signature"})
		return
	}

	var signRequest data.AxalEthPersonalSignRequest
	if err := c.ShouldBindJSON(&signRequest); err != nil {
		log.Errorf("Axal personal sign API error: invalid request data")
		c.JSON(http.StatusBadRequest, data.Message{Message: "signing data is invalid"})
		return
	}
	if err := signRequest.Validate(time.Now().UTC()); err != nil {
		log.Errorf("Axal personal sign API validation failed: %v", err)
		c.JSON(http.StatusBadRequest, data.Message{Message: "signing data is invalid"})
		return
	}

	resp, httpErr := privysigner.PrivyCli.AxalEthPersonalSign(&signRequest, hmacSignature)
	if httpErr != nil {
		log.Errorf("Axal personal sign API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Axal handler - HMAC auth only
func AxalEthSecp256k1SignTxHandler(c *gin.Context) {

	hmacSignature := c.GetHeader("auth")
	if hmacSignature == "" {
		log.Errorf("Axal eth secp256k1 sign API error: missing hmac signature")
		resp := data.Message{Message: "Missing HMAC signature"}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var secp256k1Sign data.AxalEthSecp256k1SignRequest
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

	resp, httpErr := privysigner.PrivyCli.AxalEthSecp256k1Sign(&secp256k1Sign, hmacSignature)
	if httpErr != nil {
		log.Errorf("Axal eth secp256k1 sign API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
