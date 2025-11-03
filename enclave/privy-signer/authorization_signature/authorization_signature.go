package authorizationsignature

import (
	"encoding/json"

	"github.com/getaxal/verified-signer/enclave"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	log "github.com/sirupsen/logrus"
)

// Adds the authorization signature for privy delegated signing.
// We do so by first constructing a payload that is as such:
//
//	{
//		"version": 1,
//		"method": "POST",
//		"url": url,
//		"body": body,
//		"headers": {
//			"privy-app-id": "insert-your-app-id"
//		}
//	}
//
// The headers are the headers of the http request we will be signing, the bpdy is the body of the http we are signing. We assume that there is only one header value per key (for privy headers this is the case)
// We then use the authorization key (also known as the delegated signing key) to sign the hash of the payload. It is a ECDSA-P256 signature that is then base64 encoded.
func GetAuthorizationSignature(body interface{}, methodType string, privyAuthorizationKey string, url string, privyAppId string) (string, error) {
	headermap := map[string]string{
		"privy-app-id": privyAppId,
	}

	// Make sure its not a pointer
	bodyValue := enclave.DereferenceIfPointer(body)

	payload, err := json.Marshal(map[string]interface{}{
		"body":    bodyValue,
		"headers": headermap,
		"method":  methodType,
		"url":     url,
		"version": 1,
	})

	if err != nil {
		log.Errorf("Error: %v", err)
		return "", err
	}

	canonical, err := jsoncanonicalizer.Transform(payload)

	if err != nil {
		log.Errorf("Error: %v", err)
		return "", err
	}

	signature, err := SignPayload([]byte(privyAuthorizationKey), canonical)

	if err != nil {
		log.Errorf("Error: %v", err)
		return "", err
	}

	log.Infof("auth signature completed: %s", signature)

	return string(signature), nil
}
