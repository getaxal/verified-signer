package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func signRequest(message string, secretKey []byte) string {
	// Create HMAC
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(message))

	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyAxalSignature(payload string, signature string, secretKey string) bool {
	// An empty secretKey reduces HMAC to a public function — any caller can
	// reproduce the "expected" signature.
	if secretKey == "" || signature == "" {
		return false
	}
	expectedSignature := signRequest(payload, []byte(secretKey))
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}
