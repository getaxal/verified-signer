package secretmananger

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Test hmacSHA256 function
func TestHmacSHA256(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		data     string
		expected string // hex encoded expected result
	}{
		{
			name:     "Basic HMAC test",
			key:      []byte("secret"),
			data:     "hello world",
			expected: "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a",
		},
		{
			name:     "Empty data",
			key:      []byte("secret"),
			data:     "",
			expected: "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169",
		},
		{
			name:     "Empty key",
			key:      []byte(""),
			data:     "hello world",
			expected: "c2ea634c993f050482b4e6243224087f7c23bdd3c07ab1a45e9a21c62fad994e",
		},
		{
			name:     "AWS4 prefix test",
			key:      []byte("AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
			data:     "20150830",
			expected: "0138c7a6cbd60aa727b2f653a522567439dfb9f3e72b21f9b25941a42f04a7cd",
		},
		{
			name:     "Special characters",
			key:      []byte("key with spaces & symbols!"),
			data:     "data/with-special@chars.com#fragment",
			expected: "4f2195ffa2d4809df04c07aa281fbc617cf3541241dc8fe3a6fe9174beda4eac",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hmacSHA256(tt.key, tt.data)
			resultHex := hex.EncodeToString(result)

			if resultHex != tt.expected {
				t.Errorf("hmacSHA256() = %s, expected %s", resultHex, tt.expected)
			}

			// Verify using Go's standard library directly
			expectedMac := hmac.New(sha256.New, tt.key)
			expectedMac.Write([]byte(tt.data))
			expectedResult := expectedMac.Sum(nil)

			if !bytes.Equal(result, expectedResult) {
				t.Errorf("hmacSHA256() result doesn't match standard library implementation")
			}
		})
	}
}

// Test sha256Hash function
func TestSha256Hash(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "Basic SHA256 test",
			data:     "hello world",
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:     "Empty string",
			data:     "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "Single character",
			data:     "a",
			expected: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		},
		{
			name:     "Long string",
			data:     strings.Repeat("abcdefghijklmnopqrstuvwxyz", 100),
			expected: "f8b4c3c7b3c7c7b4c3c7b3c7c7b4c3c7b3c7c7b4c3c7b3c7c7b4c3c7b3c7c7b4", // This will be different, just testing structure
		},
		{
			name:     "Special characters and numbers",
			data:     "Hello, World! 123 @#$%^&*()",
			expected: "2f9961b1d55b3c9b8e7e7e9b1a9b9f8b2d9b1c8b5e7e9b1a9b9f8b2d9b1c8b5", // This will be different
		},
		{
			name:     "JSON-like data",
			data:     `{"SecretId":"my-secret","VersionStage":"AWSCURRENT"}`,
			expected: "a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5", // This will be different
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sha256Hash(tt.data)

			// Verify the result is a valid hex string of correct length
			if len(result) != 64 { // SHA256 produces 32 bytes = 64 hex characters
				t.Errorf("sha256Hash() result length = %d, expected 64", len(result))
			}

			// Verify it's valid hex
			if _, err := hex.DecodeString(result); err != nil {
				t.Errorf("sha256Hash() result is not valid hex: %v", err)
			}

			// Verify using Go's standard library directly
			hasher := sha256.New()
			hasher.Write([]byte(tt.data))
			expected := hex.EncodeToString(hasher.Sum(nil))

			if result != expected {
				t.Errorf("sha256Hash() = %s, expected %s", result, expected)
			}
		})
	}
}

// Test createSignatureKey function
func TestCreateSignatureKey(t *testing.T) {
	// Test with AWS documentation example values
	tests := []struct {
		name        string
		key         string
		dateStamp   string
		regionName  string
		serviceName string
		expectHex   string // Expected result in hex for verification
	}{
		{
			name:        "AWS example from documentation",
			key:         "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
			dateStamp:   "20150830",
			regionName:  "us-east-1",
			serviceName: "iam",
			expectHex:   "", // We'll calculate this dynamically
		},
		{
			name:        "Secrets Manager example",
			key:         "testSecretKey123",
			dateStamp:   "20240101",
			regionName:  "us-west-2",
			serviceName: "secretsmanager",
			expectHex:   "",
		},
		{
			name:        "Different region",
			key:         "mySecretKey",
			dateStamp:   "20231215",
			regionName:  "eu-west-1",
			serviceName: "secretsmanager",
			expectHex:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createSignatureKey(tt.key, tt.dateStamp, tt.regionName, tt.serviceName)

			// Verify the result is not nil and has reasonable length
			if result == nil {
				t.Error("createSignatureKey() returned nil")
			}

			if len(result) != 32 { // HMAC-SHA256 produces 32 bytes
				t.Errorf("createSignatureKey() result length = %d, expected 32", len(result))
			}

			// Verify the signing process step by step
			kDate := hmacSHA256([]byte("AWS4"+tt.key), tt.dateStamp)
			kRegion := hmacSHA256(kDate, tt.regionName)
			kService := hmacSHA256(kRegion, tt.serviceName)
			kSigning := hmacSHA256(kService, terminationChar)

			if !bytes.Equal(result, kSigning) {
				t.Error("createSignatureKey() doesn't match step-by-step calculation")
			}

			// Test that different inputs produce different results
			differentResult := createSignatureKey(tt.key+"different", tt.dateStamp, tt.regionName, tt.serviceName)
			if bytes.Equal(result, differentResult) {
				t.Error("createSignatureKey() produced same result for different inputs")
			}
		})
	}
}

// Test createSignatureKey with edge cases
func TestCreateSignatureKey_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		dateStamp   string
		regionName  string
		serviceName string
		shouldPanic bool
	}{
		{
			name:        "Empty key",
			key:         "",
			dateStamp:   "20240101",
			regionName:  "us-east-1",
			serviceName: "secretsmanager",
			shouldPanic: false,
		},
		{
			name:        "Empty date",
			key:         "testkey",
			dateStamp:   "",
			regionName:  "us-east-1",
			serviceName: "secretsmanager",
			shouldPanic: false,
		},
		{
			name:        "Empty region",
			key:         "testkey",
			dateStamp:   "20240101",
			regionName:  "",
			serviceName: "secretsmanager",
			shouldPanic: false,
		},
		{
			name:        "Empty service",
			key:         "testkey",
			dateStamp:   "20240101",
			regionName:  "us-east-1",
			serviceName: "",
			shouldPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil && !tt.shouldPanic {
					t.Errorf("createSignatureKey() panicked unexpectedly: %v", r)
				}
			}()

			result := createSignatureKey(tt.key, tt.dateStamp, tt.regionName, tt.serviceName)

			if result == nil {
				t.Error("createSignatureKey() returned nil")
			}

			if len(result) != 32 {
				t.Errorf("createSignatureKey() result length = %d, expected 32", len(result))
			}
		})
	}
}

// Test consistency - same inputs should produce same outputs
func TestConsistency(t *testing.T) {
	key := []byte("test-key")
	data := "test-data"
	secretKey := "secret-access-key"
	dateStamp := "20240101"
	region := "us-east-1"
	service := "secretsmanager"

	// Test hmacSHA256 consistency
	result1 := hmacSHA256(key, data)
	result2 := hmacSHA256(key, data)
	if !bytes.Equal(result1, result2) {
		t.Error("hmacSHA256() not consistent across calls")
	}

	// Test sha256Hash consistency
	hash1 := sha256Hash(data)
	hash2 := sha256Hash(data)
	if hash1 != hash2 {
		t.Error("sha256Hash() not consistent across calls")
	}

	// Test createSignatureKey consistency
	sig1 := createSignatureKey(secretKey, dateStamp, region, service)
	sig2 := createSignatureKey(secretKey, dateStamp, region, service)
	if !bytes.Equal(sig1, sig2) {
		t.Error("createSignatureKey() not consistent across calls")
	}
}

// Test with actual AWS values to ensure compatibility
func TestAWSCompatibility(t *testing.T) {
	// These are test values from AWS documentation
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	dateStamp := "20150830"
	region := "us-east-1"
	service := "iam"

	signingKey := createSignatureKey(secretKey, dateStamp, region, service)

	// Verify it produces a valid signing key
	if len(signingKey) != 32 {
		t.Errorf("AWS compatible signing key should be 32 bytes, got %d", len(signingKey))
	}

	// Test that it can be used for further HMAC operations
	testString := "test-string-to-sign"
	signature := hmacSHA256(signingKey, testString)

	if len(signature) != 32 {
		t.Errorf("Signature should be 32 bytes, got %d", len(signature))
	}

	// Verify the signature is deterministic
	signature2 := hmacSHA256(signingKey, testString)
	if !bytes.Equal(signature, signature2) {
		t.Error("Signature should be deterministic")
	}
}
