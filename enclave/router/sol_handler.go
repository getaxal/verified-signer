package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handles the Solana signMessage method. It takes the users userId as a path param and a SolSignMessageRequest as the json body.
// It fetches the users delegated sol wallet from the privy backend.
func SolSignMessageTxHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Sol signMessage API error: missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	var personalSignReq privydata.SolSignMessageRequest
	err := c.ShouldBindJSON(&personalSignReq)

	if err != nil {
		log.Errorf("Sol signMessage API error tx data is invalid, sign req: %+v", personalSignReq)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = personalSignReq.ValidateTxRequest()
	if err != nil {
		log.Errorf("Sol signMessage API error tx data is invalid with err: %v", err)
		resp := privydata.Message{
			Message: "tx data is invalid",
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
		log.Errorf("Sol signMessage API error user %s does not have a delegated sol wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated sol wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.SolSignMessage(&personalSignReq, solWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Sol signMessage API error user %s could not sign tx with err: %v", privyUserId, httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles the Solana signTransaction method. It takes the users userId as a path param and a SolSignTransactionRequest as the json body.
// It fetches the users delegated sol wallet from the privy backend.
func SolSignTxHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Solana signTransaction API error missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	var transactionSignReq privydata.SolSignTransactionRequest
	err := c.ShouldBindJSON(&transactionSignReq)

	if err != nil {
		log.Errorf("Solana signTransaction API error tx data is invalid, sign req: %+v", transactionSignReq)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = transactionSignReq.ValidateTxRequest()
	if err != nil {
		log.Errorf("Solana signTransaction API error tx data is invalid with err: %v", err)
		resp := privydata.Message{
			Message: "tx data is invalid",
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
		log.Errorf("Solana signTransaction API error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated sol wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.SolSignTransaction(&transactionSignReq, solWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Solana signTransaction API error user %s could not sign tx with err: %v", privyUserId, httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles the Solana signAndSendTransaction method. It takes the users userId as a path param and a SolSignAndSendTransactionRequest as the json body.
// It fetches the users delegated sol wallet from the privy backend.
func SolSignAndSendTxHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Eth transaction send API error missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	var transactionSendReq privydata.SolSignAndSendTransactionRequest
	err := c.ShouldBindJSON(&transactionSendReq)

	if err != nil {
		log.Errorf("Sol signAndSend API error tx data is invalid, sign req: %+v", transactionSendReq)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = transactionSendReq.ValidateTxRequest()
	if err != nil {
		log.Errorf("Sol signAndSend API error tx data is invalid with err: %v", err)
		resp := privydata.Message{
			Message: "tx data is invalid",
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
		log.Errorf("Sol signAndSend API error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated eth wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.SolSignAndSendTransaction(&transactionSendReq, solWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Sol signAndSend API error user %s could not send tx with err: %v", privyUserId, err)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
