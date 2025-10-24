package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles batch Ethereum secp256k1_sign method for Axal. HMAC auth only.
func AxalBatchEthSecp256k1SignTxHandler(c *gin.Context) {
	hmacSignature := c.GetHeader("hmac-signature")
	if hmacSignature == "" {
		log.Errorf("Axal batch eth secp256k1 sign API error: missing hmac signature")
		resp := data.Message{Message: "Missing HMAC signature"}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var batchSignReq data.BatchSignRequest
	err := c.ShouldBindJSON(&batchSignReq)
	if err != nil {
		log.Errorf("Axal batch eth secp256k1 sign API error: invalid request data: %+v", batchSignReq)
		resp := data.Message{Message: "batch request data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = batchSignReq.ValidateBatchRequest()
	if err != nil {
		log.Errorf("Axal batch eth secp256k1 sign API error: validation failed: %v", err)
		resp := data.Message{Message: "batch request validation failed"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// Axal batch handler - HMAC auth only with multiple privy IDs
	resp, httpErr := privysigner.PrivyCli.AxalBatchEthSecp256k1Sign(&batchSignReq, hmacSignature)
	if httpErr != nil {
		log.Errorf("Axal batch eth secp256k1 sign API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
