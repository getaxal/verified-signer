package authorizationsignature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
)

// Test helper functions

// generateTestECDSAKeyBytes generates a test ECDSA key pair and returns bytes
func generateTestECDSAKeyBytes() (*ecdsa.PrivateKey, []byte, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Marshal to PKCS#8 format
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode to base64
	pkcs8B64 := base64.StdEncoding.EncodeToString(pkcs8Bytes)

	// Add the wallet-auth: prefix and convert to bytes
	authKey := "wallet-auth:" + pkcs8B64
	authKeyBytes := []byte(authKey)

	return privateKey, authKeyBytes, nil
}

// generateTestECDSAKeyBytesWithoutPrefix generates a key without the wallet-auth prefix
func generateTestECDSAKeyBytesWithoutPrefix() (*ecdsa.PrivateKey, []byte, error) {
	privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
	if err != nil {
		return nil, nil, err
	}

	// Remove the wallet-auth: prefix
	prefix := []byte("wallet-auth:")
	authKeyBytes = bytes.TrimPrefix(authKeyBytes, prefix)

	return privateKey, authKeyBytes, nil
}

func TestSignPayload(t *testing.T) {
	tests := []struct {
		name          string
		setupKey      func() ([]byte, *ecdsa.PrivateKey, error)
		payload       []byte
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid signing with JSON payload",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     []byte(`{"method":"POST","url":"https://api.example.com"}`),
			expectError: false,
		},
		{
			name: "Valid signing with empty payload",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     []byte{},
			expectError: false,
		},
		{
			name: "Valid signing with plain text payload",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     []byte("plain text payload"),
			expectError: false,
		},
		{
			name: "Valid signing with binary payload",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			expectError: false,
		},
		{
			name: "Valid signing with Unicode payload",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     []byte(`{"unicode":"测试","emoji":"🔐","special":"!@#$%^&*()"}`),
			expectError: false,
		},
		{
			name: "Valid signing with large payload",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     make([]byte, 10000), // 10KB of zeros
			expectError: false,
		},
		{
			name: "Valid signing without wallet-auth prefix",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytesWithoutPrefix()
				return authKeyBytes, privateKey, err
			},
			payload:     []byte(`{"test":"no_prefix"}`),
			expectError: false,
		},
		{
			name: "Invalid base64 in authorization key",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				return []byte("wallet-auth:invalid-base64!@#$"), nil, nil
			},
			payload:       []byte(`{"test":"data"}`),
			expectError:   true,
			errorContains: "failed to parse private key",
		},
		{
			name: "Empty authorization key",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				return []byte{}, nil, nil
			},
			payload:       []byte(`{"test":"data"}`),
			expectError:   true,
			errorContains: "failed to parse private key",
		},
		{
			name: "Malformed PKCS8 data",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				// Valid base64 but invalid PKCS8 content
				invalidPKCS8 := base64.StdEncoding.EncodeToString([]byte("not-valid-pkcs8-data"))
				return []byte("wallet-auth:" + invalidPKCS8), nil, nil
			},
			payload:       []byte(`{"test":"data"}`),
			expectError:   true,
			errorContains: "failed to parse private key",
		},
		{
			name: "Nil authorization key bytes",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				return nil, nil, nil
			},
			payload:       []byte(`{"test":"data"}`),
			expectError:   true,
			errorContains: "failed to parse private key",
		},
		{
			name: "Nil payload bytes",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			payload:     nil,
			expectError: false, // Should handle nil payload gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authKeyBytes, expectedPrivateKey, setupErr := tt.setupKey()
			if setupErr != nil && !tt.expectError {
				t.Fatalf("Setup failed: %v", setupErr)
			}

			signature, err := SignPayload(authKeyBytes, tt.payload)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(signature) == 0 {
				t.Error("Expected non-empty signature")
			}

			// Verify the signature is valid base64
			_, err = base64.StdEncoding.DecodeString(string(signature))
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

func TestVerifySignature(t *testing.T) {
	// Generate a test key pair
	privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	payload := []byte(`{"test":"payload","number":42}`)

	// Create a valid signature
	signature, err := SignPayload(authKeyBytes, payload)
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	tests := []struct {
		name          string
		publicKey     *ecdsa.PublicKey
		payload       []byte
		signature     []byte
		expectValid   bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid signature verification",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   signature,
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Wrong payload",
			publicKey:   &privateKey.PublicKey,
			payload:     []byte(`{"different":"payload"}`),
			signature:   signature,
			expectValid: false,
			expectError: false,
		},
		{
			name: "Wrong public key",
			publicKey: func() *ecdsa.PublicKey {
				wrongKey, _, _ := generateTestECDSAKeyBytes()
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
			signature:     []byte("invalid-base64!@#$"),
			expectValid:   false,
			expectError:   true,
			errorContains: "failed to decode signature",
		},
		{
			name:        "Empty signature",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   []byte{},
			expectValid: false,
			expectError: false,
		},
		{
			name:        "Valid base64 but invalid signature format",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   []byte(base64.StdEncoding.EncodeToString([]byte("not-a-der-signature"))),
			expectValid: false,
			expectError: false, // VerifyASN1 should handle this gracefully
		},
		{
			name:        "Nil payload",
			publicKey:   &privateKey.PublicKey,
			payload:     nil,
			signature:   signature,
			expectValid: false,
			expectError: false,
		},
		{
			name:        "Nil signature",
			publicKey:   &privateKey.PublicKey,
			payload:     payload,
			signature:   nil,
			expectValid: false,
			expectError: false,
		},
		{
			name:      "Binary payload verification",
			publicKey: &privateKey.PublicKey,
			payload:   []byte{0x00, 0x01, 0x02, 0xFF},
			signature: func() []byte {
				sig, _ := SignPayload(authKeyBytes, []byte{0x00, 0x01, 0x02, 0xFF})
				return sig
			}(),
			expectValid: true,
			expectError: false,
		},
		{
			name:      "Large payload verification",
			publicKey: &privateKey.PublicKey,
			payload:   make([]byte, 5000), // 5KB payload
			signature: func() []byte {
				largePayload := make([]byte, 5000)
				sig, _ := SignPayload(authKeyBytes, largePayload)
				return sig
			}(),
			expectValid: true,
			expectError: false,
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
				if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
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
	privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	testPayloads := [][]byte{
		[]byte(`{"simple":"test"}`),
		[]byte(`{"complex":{"nested":{"data":"value"},"array":[1,2,3]}}`),
		[]byte{}, // Empty payload
		[]byte("plain text payload"),
		[]byte(`{"unicode":"测试","emoji":"🔐","special":"!@#$%^&*()"}`),
		{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}, // Binary data
		make([]byte, 1000),                   // Large payload with zeros
	}

	for i, payload := range testPayloads {
		t.Run(fmt.Sprintf("Payload_%d", i), func(t *testing.T) {
			// Sign the payload
			signature, err := SignPayload(authKeyBytes, payload)
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
			wrongPayload := append(payload, byte(0x99))
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

// Test parsePrivateKeyFromAuthorizationKeyBytes function directly
func TestParsePrivateKeyFromAuthorizationKeyBytes(t *testing.T) {
	tests := []struct {
		name          string
		setupKey      func() ([]byte, *ecdsa.PrivateKey, error)
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid key with prefix",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytes()
				return authKeyBytes, privateKey, err
			},
			expectError: false,
		},
		{
			name: "Valid key without prefix",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				privateKey, authKeyBytes, err := generateTestECDSAKeyBytesWithoutPrefix()
				return authKeyBytes, privateKey, err
			},
			expectError: false,
		},
		{
			name: "Invalid base64",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				return []byte("wallet-auth:invalid-base64!"), nil, nil
			},
			expectError:   true,
			errorContains: "failed to decode PKCS8 key",
		},
		{
			name: "Valid base64 but invalid PKCS8",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				invalidData := base64.StdEncoding.EncodeToString([]byte("invalid-pkcs8"))
				return []byte("wallet-auth:" + invalidData), nil, nil
			},
			expectError:   true,
			errorContains: "failed to parse PKCS8 private key",
		},
		{
			name: "Empty key bytes",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				return []byte{}, nil, nil
			},
			expectError:   true,
			errorContains: "failed to parse PKCS8 private key",
		},
		{
			name: "Nil key bytes",
			setupKey: func() ([]byte, *ecdsa.PrivateKey, error) {
				return nil, nil, nil
			},
			expectError:   true,
			errorContains: "failed to parse PKCS8 private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyBytes, expectedKey, setupErr := tt.setupKey()
			if setupErr != nil && !tt.expectError {
				t.Fatalf("Setup failed: %v", setupErr)
			}

			parsedKey, err := parsePrivateKeyFromAuthorizationKeyBytes(keyBytes)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if parsedKey == nil {
				t.Error("Expected non-nil private key")
				return
			}

			// If we have an expected key, verify they match
			if expectedKey != nil {
				if parsedKey.D.Cmp(expectedKey.D) != 0 {
					t.Error("Parsed key does not match expected key")
				}
			}
		})
	}
}

// Test SecureCompare utility function
func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []byte
		expected bool
	}{
		{
			name:     "Equal bytes",
			a:        []byte("test"),
			b:        []byte("test"),
			expected: true,
		},
		{
			name:     "Different bytes",
			a:        []byte("test"),
			b:        []byte("different"),
			expected: false,
		},
		{
			name:     "Different lengths",
			a:        []byte("test"),
			b:        []byte("te"),
			expected: false,
		},
		{
			name:     "Empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "One empty",
			a:        []byte("test"),
			b:        []byte{},
			expected: false,
		},
		{
			name:     "Binary data equal",
			a:        []byte{0x00, 0x01, 0xFF, 0xFE},
			b:        []byte{0x00, 0x01, 0xFF, 0xFE},
			expected: true,
		},
		{
			name:     "Binary data different",
			a:        []byte{0x00, 0x01, 0xFF, 0xFE},
			b:        []byte{0x00, 0x01, 0xFF, 0xFF},
			expected: false,
		},
		{
			name:     "Nil slices",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "One nil slice",
			a:        []byte("test"),
			b:        nil,
			expected: false,
		},
		{
			name:     "Large equal data",
			a:        make([]byte, 1000),
			b:        make([]byte, 1000),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecureCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
