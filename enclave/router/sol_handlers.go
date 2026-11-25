package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles the Solana signTransaction method for users. JWT auth only.
// The transaction is signed with the delegated solana wallet the request names, which must
// belong to the JWT's user. It is signed and returned, not broadcast.
func UserSolSignTransactionHandler(c *gin.Context) {
	auth := c.GetHeader("auth")

	if auth == "" {
		log.Errorf("User solana signTransaction API error: missing auth")
		resp := data.Message{
			Message: "Unauthorized user",
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	// The request is deliberately not logged on failure: it carries a whole transaction.
	var signTransaction data.UserSolSignTransactionRequest
	if err := c.ShouldBindJSON(&signTransaction); err != nil {
		log.Errorf("User solana signTransaction API error: invalid request data")
		c.JSON(http.StatusBadRequest, data.Message{Message: "tx data is invalid"})
		return
	}

	if err := signTransaction.ValidateTxRequest(); err != nil {
		log.Errorf("User solana signTransaction API error tx data is invalid with err: %v", err)
		c.JSON(http.StatusBadRequest, data.Message{Message: "tx data is invalid"})
		return
	}

	// User handler - JWT auth only, privy_id extracted from JWT
	resp, httpErr := privysigner.PrivyCli.UserSolSignTransaction(&signTransaction, auth)
	if httpErr != nil {
		log.Errorf("User solana signTransaction API error could not sign tx with err: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles the Solana signTransaction method for Axal. HMAC auth only: there is no user
// session on this route, so the request names the user as well as the wallet, and the HMAC
// covers both.
func AxalSolSignTransactionHandler(c *gin.Context) {
	hmacSignature := c.GetHeader("auth")
	if hmacSignature == "" {
		log.Errorf("Axal solana signTransaction API error: missing hmac signature")
		c.JSON(http.StatusUnauthorized, data.Message{Message: "Missing HMAC signature"})
		return
	}

	var signTransaction data.AxalSolSignTransactionRequest
	if err := c.ShouldBindJSON(&signTransaction); err != nil {
		log.Errorf("Axal solana signTransaction API error: invalid request data")
		c.JSON(http.StatusBadRequest, data.Message{Message: "tx data is invalid"})
		return
	}

	if err := signTransaction.ValidateTxRequest(); err != nil {
		log.Errorf("Axal solana signTransaction API error: validation failed: %v", err)
		c.JSON(http.StatusBadRequest, data.Message{Message: "tx data is invalid"})
		return
	}

	resp, httpErr := privysigner.PrivyCli.AxalSolSignTransaction(&signTransaction, hmacSignature)
	if httpErr != nil {
		log.Errorf("Axal solana signTransaction API error: %v", httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
