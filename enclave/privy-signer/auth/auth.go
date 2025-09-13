package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// Context keys for storing values in gin and request contexts
type contextKey string

const (
	UserIDKey     contextKey = "user_id"
	PrivyTokenKey contextKey = "privy_token"
)

// PrivyClaims represents the structure of Privy JWT claims
type PrivyClaims struct {
	AppId      string `json:"aud,omitempty"`
	Expiration int64  `json:"exp,omitempty"`
	Issuer     string `json:"iss,omitempty"`
	UserId     string `json:"sub,omitempty"`
	IssuedAt   int64  `json:"iat,omitempty"`
	jwt.RegisteredClaims
}

// Valid validates the Privy JWT claims
func (c *PrivyClaims) Valid() error {
	// We'll validate in the main validation function instead
	return nil
}

// validatePrivyClaims validates Privy-specific claims
func validatePrivyClaims(claims *PrivyClaims, appID, env string) error {
	if claims.AppId != appID {
		return errors.New("aud claim must be your Privy App ID")
	}
	if claims.Issuer != "privy.io" {
		return errors.New("iss claim must be 'privy.io'")
	}

	// We added this so in dev and local we can use dummy tokens
	if env == "prod" || env == "staging" {
		if claims.Expiration < time.Now().Unix() {
			return errors.New("token is expired")
		}
	}
	if claims.UserId == "" {
		return errors.New("token does not contain user subject")
	}
	if !strings.HasPrefix(claims.UserId, "did:privy:") {
		return fmt.Errorf("invalid user DID format: expected 'did:privy:' prefix, got %s", claims.UserId)
	}
	return nil
}

// validateJWTAndExtractUserID validates a Privy JWT token using ES256 and extracts the user ID
func ValidateJWTAndExtractUserID(tokenString string, teeCfg *enclave.TEEConfig) (string, error) {
	if tokenString == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	if teeCfg.Privy.JWTVerificationKey == "" {
		return "", fmt.Errorf("verification key is not configured")
	}

	if teeCfg.Privy.AppID == "" {
		return "", fmt.Errorf("app ID is not configured")
	}

	// Format the PEM key properly - handle both escaped newlines and space-separated format
	formattedVerificationKey := teeCfg.Privy.JWTVerificationKey

	// First try to handle escaped newlines (for JSON strings)
	formattedVerificationKey = strings.ReplaceAll(formattedVerificationKey, "\\n", "\n")

	// If the key is still single-line (spaces instead of newlines), format it properly
	if !strings.Contains(formattedVerificationKey, "\n") {
		// This handles the AWS Secrets Manager format where spaces are used instead of newlines
		formattedVerificationKey = strings.ReplaceAll(formattedVerificationKey, "-----BEGIN PUBLIC KEY----- ", "-----BEGIN PUBLIC KEY-----\n")
		formattedVerificationKey = strings.ReplaceAll(formattedVerificationKey, " -----END PUBLIC KEY-----", "\n-----END PUBLIC KEY-----")

		// Add newlines every 64 characters in the key body (standard PEM format)
		lines := strings.Split(formattedVerificationKey, "\n")
		if len(lines) >= 3 {
			// lines[0] should be "-----BEGIN PUBLIC KEY-----"
			// lines[1] should be the key data
			// lines[2] should be "-----END PUBLIC KEY-----"
			keyData := lines[1]
			if len(keyData) > 64 {
				var formattedKeyData strings.Builder
				for i := 0; i < len(keyData); i += 64 {
					end := i + 64
					if end > len(keyData) {
						end = len(keyData)
					}
					formattedKeyData.WriteString(keyData[i:end])
					if end < len(keyData) {
						formattedKeyData.WriteString("\n")
					}
				}
				lines[1] = formattedKeyData.String()
				formattedVerificationKey = strings.Join(lines, "\n")
			}
		}
	}

	// Let's also try to decode the JWT header and payload to see what's inside
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		// Decode header
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err == nil {
			log.Infof("JWT Header: %s", string(headerBytes))
		}

		// Decode payload
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			log.Infof("JWT payload: %s", string(payloadBytes))
		}
	}

	// keyFunc validates the signing method and returns the verification key
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "ES256" {
			log.Infof("Unexpected JWT signing method: %s", token.Method.Alg())
			return nil, fmt.Errorf("unexpected JWT signing method=%v", token.Header["alg"])
		}

		// Parse the ECDSA public key from PEM format using the formatted key
		key, err := jwt.ParseECPublicKeyFromPEM([]byte(formattedVerificationKey))
		if err != nil {
			log.Errorf("Failed to parse ECDSA public key: %v", err)
			return nil, fmt.Errorf("failed to parse verification key: %w", err)
		}

		log.Info("Successfully parsed ECDSA public key")
		return key, nil
	}

	// Parse and validate the JWT token
	log.Info("Parsing JWT token")
	token, err := jwt.ParseWithClaims(tokenString, &PrivyClaims{}, keyFunc)
	if err != nil {
		log.Errorf("JWT parsing failed: %v", err)
		return "", fmt.Errorf("JWT signature is invalid: %w", err)
	}

	if token.Valid {
		log.Info("Successfuly parsed token")
	}

	// Parse the JWT claims into our custom struct
	privyClaim, ok := token.Claims.(*PrivyClaims)
	if !ok {
		return "", fmt.Errorf("JWT does not have all the necessary claims")
	}

	// Validate Privy-specific claims
	if err := validatePrivyClaims(privyClaim, teeCfg.Privy.AppID, teeCfg.Environment); err != nil {
		return "", fmt.Errorf("JWT claims are invalid: %w", err)
	}

	return privyClaim.UserId, nil
}

// GetPrivyTokenFromGin retrieves the privy token from gin context
func GetPrivyTokenFromGin(c *gin.Context) string {
	return c.GetString(string(PrivyTokenKey))
}
