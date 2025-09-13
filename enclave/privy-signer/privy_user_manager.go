package privysigner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/getaxal/verified-signer/enclave/privy-signer/auth"
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
)

// Gets a user given a Privy userID. It also checks to see if the user already has a delagted eth wallet, if it does not it will create one for them.
func (cli *PrivyClient) GetUser(privyToken string) (*data.PrivyUser, *data.HttpError) {
	privyId, err := auth.ValidateJWTAndExtractUserID(privyToken, cli.privyConfig.JWTVerificationKey, cli.privyConfig.AppID, cli.Environment)
	if err != nil {
		log.Errorf("Unable to parse privy token: %v", err)
		return nil, &data.HttpError{
			Code: 401,
			Message: data.Message{
				Message: "Unauthorized User",
			},
		}
	}

	if item := cli.userCache.Get(privyId); item != nil {
		log.Infof("Cache Hit: %s", privyId)
		value := item.Value()
		return &value, nil
	}

	url := fmt.Sprintf("%s%s", cli.baseUrl, GET_USER_PATH.Build(privyId))

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)
	if err != nil {
		log.Errorf("Error making request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		httpErr := handlePrivyError(res)
		return nil, httpErr
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	var user data.PrivyUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	userWithWallet, httpErr := cli.createUserWalletsIfNotExists(user, privyId)

	if httpErr != nil {
		return nil, httpErr
	}

	cli.userCache.Set(privyId, *userWithWallet, ttlcache.DefaultTTL)

	return userWithWallet, nil
}

// Checks to see if a user has a delegated eth wallet, if the user does not it will create one for them
func (cli *PrivyClient) createUserWalletsIfNotExists(user data.PrivyUser, userId string) (*data.PrivyUser, *data.HttpError) {
	if user.GetUsersEthDelegatedWallet() != nil {
		log.Infof("User %s has a linked address", userId)
		return &user, nil
	}

	log.Infof("User %s doesnt have a linked address, creating one for them", userId)

	url := fmt.Sprintf("%s%s", cli.baseUrl, CREATE_WALLET_PATH.Build(userId))

	walletCreateReq := data.NewCreateEthWalletRequest(cli.privyConfig.DelegatedActionsKeyId)

	requestBody, err := json.Marshal(walletCreateReq)

	if err != nil {
		log.Errorf("failed to marshal wallet create request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))

	if err != nil {
		log.Errorf("failed to create request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	cli.addStandardPrivyHeaders(req)

	res, err := cli.client.Do(req)

	if err != nil {
		log.Errorf("error sending the client request: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != http.StatusOK {
		httpErr := handlePrivyError(res)
		return nil, httpErr
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	var createWalletResp data.CreateWalletResponse
	if err := json.Unmarshal(body, &createWalletResp); err != nil {
		log.Errorf("unable to marshall response data:%v", string(body))
		return nil, &data.HttpError{
			Code: 500,
			Message: data.Message{
				Message: "Internal Server Error",
			},
		}
	}

	// We check the response for the delegated eth wallet and then we add it to the user
	for _, linkedAcc := range createWalletResp.LinkedAccounts {
		if linkedAcc.Delegated && linkedAcc.ChainType == "ethereum" {
			user.LinkedAccounts = append(user.LinkedAccounts, *linkedAcc)
			return &user, nil
		}
	}

	return nil, &data.HttpError{
		Code: 500,
		Message: data.Message{
			Message: "Internal Server Error",
		},
	}
}
