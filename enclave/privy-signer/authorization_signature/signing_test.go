package authorizationsignature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Mock private key generation for testing
func generateTestECDSAKey() (*ecdsa.PrivateKey, string, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	// Marshal to PKCS#8 format
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", err
	}

	// Encode to base64
	pkcs8B64 := base64.StdEncoding.EncodeToString(pkcs8Bytes)

	// Add the wallet-auth: prefix
	authKey := "wallet-auth:" + pkcs8B64

	return privateKey, authKey, nil
}

func TestSignPayload(t *testing.T) {
	tests := []struct {
		name          string
		setupKey      func() (string, *ecdsa.PrivateKey, error)
		payload       string
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid signing",
			setupKey: func() (string, *ecdsa.PrivateKey, error) {
				privateKey, authKey, err := generateTestECDSAKey()
				return authKey, privateKey, err
			},
			payload:     `{"method":"POST","url":"https://api.example.com"}`,
			expectError: false,
		},
		{
			name: "Empty payload",
			setupKey: func() (string, *ecdsa.PrivateKey, error) {
				privateKey, authKey, err := generateTestECDSAKey()
				return authKey, privateKey, err
			},
			payload:     "",
			expectError: false,
		},
		{
			name: "JSON payload with special characters",
			setupKey: func() (string, *ecdsa.PrivateKey, error) {
				privateKey, authKey, err := generateTestECDSAKey()
				return authKey, privateKey, err
			},
			payload:     `{"special":"chars!@#$%^&*()","unicode":"测试","newline":"\n"}`,
			expectError: false,
		},
		{
			name: "Invalid base64 in authorization key",
			setupKey: func() (string, *ecdsa.PrivateKey, error) {
				return "wallet-auth:invalid-base64!", nil, nil
			},
			payload:       `{"test":"data"}`,
			expectError:   true,
			errorContains: "failed to parse private key",
		},
		{
			name: "Empty authorization key",
			setupKey: func() (string, *ecdsa.PrivateKey, error) {
				return "", nil, nil
			},
			payload:       `{"test":"data"}`,
			expectError:   true,
			errorContains: "failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authKey, expectedPrivateKey, setupErr := tt.setupKey()
			if setupErr != nil && !tt.expectError {
				t.Fatalf("Setup failed: %v", setupErr)
			}

			signature, err := SignPayload(authKey, tt.payload)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if signature == "" {
				t.Error("Expected non-empty signature")
			}

			// Verify the signature is valid base64
			_, err = base64.StdEncoding.DecodeString(signature)
			if err != nil {
				t.Errorf("Signature is not valid base64: %v", err)
			}

			// If we have the expected private key, verify the signature
			if expectedPrivateKey != nil {
				valid, err := VerifySignature(&expectedPrivateKey.PublicKey, tt.payload, signature)
				if err != nil {
					t.Errorf("Failed to verify signature: %v", err)
				}
				if !valid {
					t.Error("Signature verification failed")
				}
			}
		})
	}
}

func TestParsePrivateKeyFromAuthorizationKey(t *testing.T) {
	tests := []struct {
		name          string
		setupKey      func() (*ecdsa.PrivateKey, string, error)
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid authorization key",
			setupKey: func() (*ecdsa.PrivateKey, string, error) {
				return generateTestECDSAKey()
			},
			expectError: false,
		},
		{
			name: "Authorization key without prefix",
			setupKey: func() (*ecdsa.PrivateKey, string, error) {
				privateKey, authKey, err := generateTestECDSAKey()
				// Remove the prefix
				authKey = strings.TrimPrefix(authKey, "wallet-auth:")
				return privateKey, authKey, err
			},
			expectError: false, // Should still work, just no prefix to remove
		},
		{
			name: "Invalid base64",
			setupKey: func() (*ecdsa.PrivateKey, string, error) {
				return nil, "wallet-auth:invalid-base64!", nil
			},
			expectError: true,
		},
		{
			name: "Empty string",
			setupKey: func() (*ecdsa.PrivateKey, string, error) {
				return nil, "", nil
			},
			expectError: true,
		},
		{
			name: "Valid base64 but not PKCS#8",
			setupKey: func() (*ecdsa.PrivateKey, string, error) {
				invalidData := base64.StdEncoding.EncodeToString([]byte("not-pkcs8-data"))
				return nil, "wallet-auth:" + invalidData, nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedPrivateKey, authKey, setupErr := tt.setupKey()
			if setupErr != nil && !tt.expectError {
				t.Fatalf("Setup failed: %v", setupErr)
			}

			privateKey, err := parsePrivateKeyFromAuthorizationKey(authKey)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if privateKey == nil {
				t.Error("Expected non-nil private key")
			}

			if privateKey == nil {
				t.Error("Expected non-nil private key")
				return // Exit early to avoid nil pointer dereference
			}

			// Verify the curve is P-256
			if privateKey.Curve != elliptic.P256() {
				t.Error("Expected P-256 curve")
			}

			// If we have an expected key, compare the D values
			if expectedPrivateKey != nil {
				if privateKey.D.Cmp(expectedPrivateKey.D) != 0 {
					t.Error("Private key D values don't match")
				}
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	// Generate a test key pair
	privateKey, authKey, err := generateTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	payload := `{"test":"payload","number":42}`

	// Create a valid signature
	signature, err := SignPayload(authKey, payload)
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	tests := []struct {
		name          string
		publicKey     *ecdsa.PublicKey
		payload       string
		signature     string
		expectValid   bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid signature",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   signature,
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Wrong payload",
			publicKey:   &privateKey.PublicKey,
			payload:     `{"different":"payload"}`,
			signature:   signature,
			expectValid: false,
			expectError: false,
		},
		{
			name: "Wrong public key",
			publicKey: func() *ecdsa.PublicKey {
				wrongKey, _, _ := generateTestECDSAKey()
				return &wrongKey.PublicKey
			}(),
			payload:     payload,
			signature:   signature,
			expectValid: false,
			expectError: false,
		},
		{
			name:          "Invalid base64 signature",
			publicKey:     &privateKey.PublicKey,
			payload:       payload,
			signature:     "invalid-base64!",
			expectValid:   false,
			expectError:   true,
			errorContains: "failed to decode signature",
		},
		{
			name:        "Empty signature",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   "",
			expectValid: false,
			expectError: false,
		},
		{
			name:        "Valid base64 but invalid signature format",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   base64.StdEncoding.EncodeToString([]byte("not-a-signature")),
			expectValid: false,
			expectError: false, // VerifyASN1 should handle this gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifySignature(tt.publicKey, tt.payload, tt.signature)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.expectValid, valid)
			}
		})
	}
}

// Test end-to-end signing and verification
func TestSignAndVerifyRoundTrip(t *testing.T) {
	privateKey, authKey, err := generateTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	testPayloads := []string{
		`{"simple":"test"}`,
		`{"complex":{"nested":{"data":"value"},"array":[1,2,3]}}`,
		"",
		"plain text payload",
		`{"unicode":"测试","emoji":"🔐","special":"!@#$%^&*()"}`,
	}

	for i, payload := range testPayloads {
		t.Run(fmt.Sprintf("Payload_%d", i), func(t *testing.T) {
			// Sign the payload
			signature, err := SignPayload(authKey, payload)
			if err != nil {
				t.Fatalf("Failed to sign payload: %v", err)
			}

			// Verify the signature
			valid, err := VerifySignature(&privateKey.PublicKey, payload, signature)
			if err != nil {
				t.Fatalf("Failed to verify signature: %v", err)
			}

			if !valid {
				t.Error("Signature verification failed")
			}

			// Verify with wrong payload should fail
			wrongPayload := payload + "modified"
			valid, err = VerifySignature(&privateKey.PublicKey, wrongPayload, signature)
			if err != nil {
				t.Fatalf("Failed to verify wrong payload: %v", err)
			}

			if valid {
				t.Error("Expected signature verification to fail with wrong payload")
			}
		})
	}
}
