package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test key pair for ES256 signing
var (
	testPrivateKey   *ecdsa.PrivateKey
	testPublicKeyPEM string
)

func init() {
	// Generate a test ECDSA key pair for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Failed to generate test key: " + err.Error())
	}
	testPrivateKey = privateKey

	// Convert public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic("Failed to marshal public key: " + err.Error())
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	testPublicKeyPEM = string(pem.EncodeToMemory(publicKeyPEM))
}

// Helper function to create a test JWT token using ES256
func createTestJWT(claims *PrivyClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(testPrivateKey)
}

func TestValidateJWTAndExtractUserID_ValidToken(t *testing.T) {
	appID := "test-app-id"
	userDID := "did:privy:test123456789"

	claims := &PrivyClaims{
		UserId:     userDID,
		Issuer:     "privy.io",
		AppId:      appID,
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
	}

	token, err := createTestJWT(claims)
	require.NoError(t, err)

	userID, err := ValidateJWTAndExtractUserID(token, testPublicKeyPEM, appID)
	assert.NoError(t, err)
	assert.Equal(t, userDID, userID)
}

func TestValidateJWTAndExtractUserID_InvalidSignature(t *testing.T) {
	appID := "test-app-id"
	userDID := "did:privy:test123456789"

	claims := &PrivyClaims{
		UserId:     userDID,
		Issuer:     "privy.io",
		AppId:      appID,
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
	}

	// Create token with our test key
	token, err := createTestJWT(claims)
	require.NoError(t, err)

	// Try to validate with wrong public key (should fail)
	wrongPublicKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwrongkey123456789wrongkey123456789wrongkey123456789wrongkey123456789wrongkey==
-----END PUBLIC KEY-----`

	userID, err := ValidateJWTAndExtractUserID(token, wrongPublicKey, appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "JWT signature is invalid")
}

func TestValidateJWTAndExtractUserID_ExpiredToken(t *testing.T) {
	appID := "test-app-id"
	userDID := "did:privy:test123456789"

	claims := &PrivyClaims{
		UserId:     userDID,
		Issuer:     "privy.io",
		AppId:      appID,
		Expiration: time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		IssuedAt:   time.Now().Add(-2 * time.Hour).Unix(),
	}

	token, err := createTestJWT(claims)
	require.NoError(t, err)

	userID, err := ValidateJWTAndExtractUserID(token, testPublicKeyPEM, appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestValidateJWTAndExtractUserID_InvalidDIDFormat(t *testing.T) {
	appID := "test-app-id"

	claims := &PrivyClaims{
		UserId:     "user123456789", // Invalid DID format (missing did:privy: prefix)
		Issuer:     "privy.io",
		AppId:      appID,
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
	}

	token, err := createTestJWT(claims)
	require.NoError(t, err)

	userID, err := ValidateJWTAndExtractUserID(token, testPublicKeyPEM, appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "invalid user DID format")
}

func TestValidateJWTAndExtractUserID_WrongAppID(t *testing.T) {
	appID := "test-app-id"
	wrongAppID := "wrong-app-id"
	userDID := "did:privy:test123456789"

	claims := &PrivyClaims{
		UserId:     userDID,
		Issuer:     "privy.io",
		AppId:      appID,
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
	}

	token, err := createTestJWT(claims)
	require.NoError(t, err)

	userID, err := ValidateJWTAndExtractUserID(token, testPublicKeyPEM, wrongAppID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "aud claim must be your Privy App ID")
}

func TestValidateJWTAndExtractUserID_WrongIssuer(t *testing.T) {
	appID := "test-app-id"
	userDID := "did:privy:test123456789"

	claims := &PrivyClaims{
		UserId:     userDID,
		Issuer:     "wrong.issuer.com", // Wrong issuer
		AppId:      appID,
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
	}

	token, err := createTestJWT(claims)
	require.NoError(t, err)

	userID, err := ValidateJWTAndExtractUserID(token, testPublicKeyPEM, appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "iss claim must be 'privy.io'")
}

func TestValidateJWTAndExtractUserID_EmptyToken(t *testing.T) {
	appID := "test-app-id"

	userID, err := ValidateJWTAndExtractUserID("", testPublicKeyPEM, appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "token cannot be empty")
}

func TestValidateJWTAndExtractUserID_EmptyVerificationKey(t *testing.T) {
	appID := "test-app-id"
	token := "some.jwt.token"

	userID, err := ValidateJWTAndExtractUserID(token, "", appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "verification key is not configured")
}

func TestValidateJWTAndExtractUserID_EmptyAppID(t *testing.T) {
	token := "some.jwt.token"

	userID, err := ValidateJWTAndExtractUserID(token, testPublicKeyPEM, "")
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "app ID is not configured")
}

func TestValidateJWTAndExtractUserID_WrongSigningMethod(t *testing.T) {
	appID := "test-app-id"
	userDID := "did:privy:test123456789"

	// Create a token with HS256 instead of ES256
	claims := &PrivyClaims{
		UserId:     userDID,
		Issuer:     "privy.io",
		AppId:      appID,
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("some-secret"))
	require.NoError(t, err)

	userID, err := ValidateJWTAndExtractUserID(tokenString, testPublicKeyPEM, appID)
	assert.Error(t, err)
	assert.Empty(t, userID)
	assert.Contains(t, err.Error(), "unexpected JWT signing method")
}
