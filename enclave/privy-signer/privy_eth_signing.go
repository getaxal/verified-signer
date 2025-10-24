package privysigner

import (
	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	log "github.com/sirupsen/logrus"
)

// User signing - JWT auth only, privy_id extracted from JWT
func (cli *PrivyClient) UserEthSecp256k1Sign(signReq *data.UserEthSecp256k1SignRequest, authString string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// Validate JWT and get privy_id
	privyId, httpErr := cli.ValidateUserAuthForSigningRequest(authString)
	if httpErr != nil {
		log.Errorf("invalid user auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	// Execute privy signing directly with user request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(*signReq, privyId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal signing - HMAC auth only, privy_id from request body
func (cli *PrivyClient) AxalEthSecp256k1Sign(signReq *data.AxalEthSecp256k1SignRequest, hmacSignature string) (*data.EthSecp256k1SignResponse, *data.HttpError) {
	// Validate HMAC and get privy_id from request
	privyId, httpErr := cli.ValidateAxalAuthForSigningRequest(hmacSignature, signReq)
	if httpErr != nil {
		log.Errorf("invalid axal auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	// Execute privy signing directly with axal request
	var resp data.EthSecp256k1SignResponse
	if err := cli.executePrivySigningRequest(*signReq, privyId, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Axal batch signing - HMAC auth only, processes multiple signing requests
func (cli *PrivyClient) AxalBatchEthSecp256k1Sign(batchReq *data.BatchSignRequest, hmacSignature string) (*data.BatchSignResponse, *data.HttpError) {
	// Validate HMAC for the entire batch request
	if httpErr := cli.ValidateAxalBatchAuthForSigningRequest(hmacSignature, batchReq); httpErr != nil {
		log.Errorf("invalid axal batch auth with err: %v", httpErr.Message.Message)
		return nil, httpErr
	}

	totalRequests := len(batchReq.SigningRequests)
	signatures := make([]data.SignatureResult, totalRequests)
	successCount := 0
	failCount := 0

	// Process each signing request
	for i, signReq := range batchReq.SigningRequests {
		// Convert to individual AxalEthSecp256k1SignRequest
		individualReq := data.AxalEthSecp256k1SignRequest{
			Method: "secp256k1_sign",
			Params: struct {
				Hash string `json:"hash"`
			}{
				Hash: signReq.Hash,
			},
			PrivyID: signReq.PrivyID,
		}

		// Execute individual signing (skip individual HMAC validation since we validated the batch)
		var resp data.EthSecp256k1SignResponse
		if err := cli.executePrivySigningRequest(individualReq, signReq.PrivyID, &resp); err != nil {
			signatures[i] = data.SignatureResult{
				Index:   signReq.Index,
				Success: false,
				Error:   err.Message.Message,
			}
			failCount++
			log.Warnf("failed to sign request %d for privy_id %s: %v", i, signReq.PrivyID, err.Message.Message)
		} else {
			signatures[i] = data.SignatureResult{
				Index:     signReq.Index,
				Success:   true,
				Signature: resp.Data.Signature,
			}
			successCount++
		}
	}

	log.Infof("batch signing completed: %d successful, %d failed out of %d total", successCount, failCount, totalRequests)

	return &data.BatchSignResponse{
		TotalRequests:   totalRequests,
		SuccessfulSigns: successCount,
		FailedSigns:     failCount,
		Signatures:      signatures,
	}, nil
}
