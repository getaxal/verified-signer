package authorizationsignature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// SignPayload signs the canonicalized JSON payload using ECDSA (P-256 + SHA-256).
//
// privateKeyString - A string containing your authorization key with the 'wallet-api:' prefix included.
// payload - JSON payload to sign, serialized to a string
//
// Returns the base64-encoded DER signature or an error.
func SignPayload(privyAuthorizationKey, payload string) (string, error) {
	privateKey, err := parsePrivateKeyFromAuthorizationKey(privyAuthorizationKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Hash the payload using SHA-256
	hash := sha256.Sum256([]byte(payload))

	// Sign the hash
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	// Base64 encode the signature
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	return signatureB64, nil
}

// We parse the ecdsa key from the authorization key here
func parsePrivateKeyFromAuthorizationKey(privyAuthorizationKey string) (*ecdsa.PrivateKey, error) {
	pkcs8B64 := strings.TrimPrefix(privyAuthorizationKey, "wallet-auth:")
	pkcs8Bytes, err := base64.StdEncoding.DecodeString(pkcs8B64)
	if err != nil {
		return nil, err
	}

	// This handles PKCS#8 parsing automatically
	key, err := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
	if err != nil {
		return nil, err
	}

	// Type assert to ECDSA private key
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key provided is not an ECDSA private key")
	}

	return ecdsaKey, nil
}

// Utility function to verify the signature (for testing purposes)
func VerifySignature(publicKey *ecdsa.PublicKey, payload, signatureB64 string) (bool, error) {
	// Decode the base64 signature
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}
	// Hash the payload
	hash := sha256.Sum256([]byte(payload))

	// Verify the signature
	valid := ecdsa.VerifyASN1(publicKey, hash[:], signature)
	return valid, nil
}
