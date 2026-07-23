package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles EIP-712 typed data signing for users. JWT auth only.
// The full typed data JSON is hashed in-enclave before signing.
func UserEthSignTypedDataHandler(c *gin.Context) {
	auth := c.GetHeader("auth")

	if auth == "" {
		log.Errorf("User eth signTypedData API error: missing auth")
		resp := data.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var typedDataSign data.UserEthSignTypedDataRequest
	err := c.ShouldBindJSON(&typedDataSign)

	if err != nil {
		log.Errorf("User eth signTypedData API error tx data is invalid")
		resp := data.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = typedDataSign.ValidateTxRequest()
	if err != nil {
		log.Errorf("User eth signTypedData API error tx data is invalid with err: %v", err)
		resp := data.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.UserEthSignTypedData(&typedDataSign, auth)
	if httpErr != nil {
		log.Errorf("User eth signTypedData API error could not sign with err: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles EIP-712 typed data signing for axal initiated requests. HMAC auth only.
func AxalEthSignTypedDataHandler(c *gin.Context) {
	hmacSignature := c.GetHeader("auth")
	if hmacSignature == "" {
		log.Errorf("Axal eth signTypedData API error: missing hmac signature")
		resp := data.Message{Message: "Missing HMAC signature"}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var typedDataSign data.AxalEthSignTypedDataRequest
	err := c.ShouldBindJSON(&typedDataSign)
	if err != nil {
		log.Errorf("Axal eth signTypedData API error: invalid request data")
		resp := data.Message{Message: "tx data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = typedDataSign.ValidateTxRequest()
	if err != nil {
		log.Errorf("Axal eth signTypedData API error: validation failed: %v", err)
		resp := data.Message{Message: "tx data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.AxalEthSignTypedData(&typedDataSign, hmacSignature)
	if httpErr != nil {
		log.Errorf("Axal eth signTypedData API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles EIP-191 personal_sign for users. JWT auth only.
// The message is hashed in-enclave before signing.
func UserEthPersonalSignHandler(c *gin.Context) {
	auth := c.GetHeader("auth")

	if auth == "" {
		log.Errorf("User eth personalSign API error: missing auth")
		resp := data.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var personalSign data.UserEthPersonalSignRequest
	err := c.ShouldBindJSON(&personalSign)

	if err != nil {
		log.Errorf("User eth personalSign API error tx data is invalid")
		resp := data.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = personalSign.ValidateTxRequest()
	if err != nil {
		log.Errorf("User eth personalSign API error tx data is invalid with err: %v", err)
		resp := data.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.UserEthPersonalSign(&personalSign, auth)
	if httpErr != nil {
		log.Errorf("User eth personalSign API error could not sign with err: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles EIP-191 personal_sign for axal initiated requests. HMAC auth only.
func AxalEthPersonalSignHandler(c *gin.Context) {
	hmacSignature := c.GetHeader("auth")
	if hmacSignature == "" {
		log.Errorf("Axal eth personalSign API error: missing hmac signature")
		resp := data.Message{Message: "Missing HMAC signature"}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var personalSign data.AxalEthPersonalSignRequest
	err := c.ShouldBindJSON(&personalSign)
	if err != nil {
		log.Errorf("Axal eth personalSign API error: invalid request data")
		resp := data.Message{Message: "tx data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = personalSign.ValidateTxRequest()
	if err != nil {
		log.Errorf("Axal eth personalSign API error: validation failed: %v", err)
		resp := data.Message{Message: "tx data is invalid"}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.AxalEthPersonalSign(&personalSign, hmacSignature)
	if httpErr != nil {
		log.Errorf("Axal eth personalSign API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
