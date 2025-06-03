package router

import (
	"net/http"

	privysigner "github.com/getaxal/verified-signer/enclave/privy-signer"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handler for a simple Ping health check
func PingCheckHandler(c *gin.Context) {
	resp := privydata.Message{
		Message: "pong from tee",
	}

	c.JSON(http.StatusOK, resp)
}

// Handles the Ethereum personalSign method. It takes the users userId as a path param and a EthPersonalSignRequest as the json body.
// It fetches the users delegated eth wallet from the privy backend.
func EthPersonalSignTxHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Eth personal sign API error: missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	var personalSignReq privydata.EthPersonalSignRequest
	err := c.ShouldBindJSON(&personalSignReq)

	if err != nil {
		log.Errorf("Eth personal sign API error tx data is invalid, sign req: %+v", personalSignReq)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = personalSignReq.ValidateTxRequest()
	if err != nil {
		log.Errorf("Eth transaction sign API error tx data is invalid with err: %v", err)
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

	ethWallet := user.GetUsersEthDelegatedWallet()
	if ethWallet == nil || ethWallet.WalletID == "" {
		log.Errorf("Eth personal sign API error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated eth wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.EthPersonalSign(&personalSignReq, ethWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Eth personal sign API error user %s could not sign tx with err: %v", privyUserId, httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles the Ethereum eth_SignTransaction method. It takes the users userId as a path param and a EthSignTransactionRequest as the json body.
// It fetches the users delegated eth wallet from the privy backend.
func EthTransactionSignTxHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Eth transaction sign API error missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	var transactionSignReq privydata.EthSignTransactionRequest
	err := c.ShouldBindJSON(&transactionSignReq)

	if err != nil {
		log.Errorf("Eth transaction sign API error tx data is invalid, sign req: %+v", transactionSignReq)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = transactionSignReq.ValidateTxRequest()
	if err != nil {
		log.Errorf("Eth transaction sign API error tx data is invalid with err: %v", err)
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

	ethWallet := user.GetUsersEthDelegatedWallet()
	if ethWallet == nil || ethWallet.WalletID == "" {
		log.Errorf("Eth transaction sign API error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated eth wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.EthSignTransaction(&transactionSignReq, ethWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Eth transaction sign API error user %s could not sign tx with err: %v", privyUserId, httpErr.Message.Message)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Handles the Ethereum eth_SendTransaction method. It takes the users userId as a path param and a EthSendTransactionRequest as the json body.
// It fetches the users delegated eth wallet from the privy backend.
func EthTransactionSendTxHandler(c *gin.Context) {
	privyUserId := c.Param("userId")

	if privyUserId == "" {
		log.Errorf("Eth transaction send API error missing user id")
		resp := privydata.Message{
			Message: "privy user id query parameter is required",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	var transactionSendReq privydata.EthSendTransactionRequest
	err := c.ShouldBindJSON(&transactionSendReq)

	if err != nil {
		log.Errorf("Eth transaction send API error tx data is invalid, sign req: %+v", transactionSendReq)
		resp := privydata.Message{
			Message: "tx data is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	err = transactionSendReq.ValidateTxRequest()
	if err != nil {
		log.Errorf("Eth transaction send API error tx data is invalid with err: %v", err)
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

	ethWallet := user.GetUsersEthDelegatedWallet()
	if ethWallet == nil || ethWallet.WalletID == "" {
		log.Errorf("Eth transaction send API error user %s does not have a delegated eth wallet", privyUserId)
		resp := privydata.Message{
			Message: "user does not have an delegated eth wallet",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp, httpErr := privysigner.PrivyCli.EthSendTransaction(&transactionSendReq, ethWallet.WalletID)
	if httpErr != nil {
		log.Errorf("Eth transaction send API error user %s could not send tx with err: %v", privyUserId, err)
		c.JSON(httpErr.Code, httpErr.Message)
		return
	}

	c.JSON(http.StatusOK, resp)
}
