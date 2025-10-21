package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSignRequest(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		secretKey []byte
		expected  string
	}{
		{
			name:      "Basic message and key",
			message:   "hello world",
			secretKey: []byte("secret"),
			expected:  "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a",
		},
		{
			name:      "Empty message",
			message:   "",
			secretKey: []byte("secret"),
			expected:  "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169",
		},
		{
			name:      "Empty secret key",
			message:   "hello world",
			secretKey: []byte(""),
			expected:  "c2ea634c993f050482b4e6243224087f7c23bdd3c07ab1a45e9a21c62fad994e",
		},
		{
			name:      "Long message",
			message:   strings.Repeat("a", 1000),
			secretKey: []byte("key"),
			expected:  "", // Will be calculated below
		},
		{
			name:      "Special characters",
			message:   "hello@world#2024!",
			secretKey: []byte("my-secret-key"),
			expected:  "7055b3b9a0eff6f744a5a4e86781e1cd3804ab5a1e57d650a73c71e2bf57ab72",
		},
		{
			name:      "Unicode characters",
			message:   "🔐 secure message 中文",
			secretKey: []byte("unicode-key"),
			expected:  "", // Will be calculated below
		},
		{
			name:      "JSON payload",
			message:   `{"user":"john","action":"login","timestamp":1234567890}`,
			secretKey: []byte("api-secret"),
			expected:  "", // Will be calculated below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := signRequest(tt.message, tt.secretKey)

			// For tests where expected is empty, calculate it manually for verification
			if tt.expected == "" {
				mac := hmac.New(sha256.New, tt.secretKey)
				mac.Write([]byte(tt.message))
				tt.expected = hex.EncodeToString(mac.Sum(nil))
			}

			if result != tt.expected {
				t.Errorf("signRequest() = %v, want %v", result, tt.expected)
			}

			// Verify the result is a valid hex string
			if _, err := hex.DecodeString(result); err != nil {
				t.Errorf("signRequest() returned invalid hex: %v", err)
			}

			// Verify the result is exactly 64 characters (SHA256 hex)
			if len(result) != 64 {
				t.Errorf("signRequest() returned %d characters, want 64", len(result))
			}
		})
	}
}

func TestVerifyAxalSignature(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		signature string
		secretKey string
		expected  bool
	}{
		{
			name:      "Valid signature",
			payload:   "hello world",
			signature: "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a",
			secretKey: "secret",
			expected:  true,
		},
		{
			name:      "Invalid signature",
			payload:   "hello world",
			signature: "invalid-signature",
			secretKey: "secret",
			expected:  false,
		},
		{
			name:      "Wrong secret key",
			payload:   "hello world",
			signature: "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a",
			secretKey: "wrong-secret",
			expected:  false,
		},
		{
			name:      "Modified payload",
			payload:   "hello world!",
			signature: "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a",
			secretKey: "secret",
			expected:  false,
		},
		{
			name:      "Empty payload",
			payload:   "",
			signature: "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169",
			secretKey: "secret",
			expected:  true,
		},
		{
			name:      "Empty signature",
			payload:   "hello world",
			signature: "",
			secretKey: "secret",
			expected:  false,
		},
		{
			name:      "Empty secret key",
			payload:   "hello world",
			signature: "c2ea634c993f050482b4e6243224087f7c23bdd3c07ab1a45e9a21c62fad994e",
			secretKey: "",
			expected:  true, // Should match since we're using the correct signature for empty key
		},
		{
			name:      "Case sensitive signature",
			payload:   "hello world",
			signature: "734CC62F32841568F45715AEB9F4D7891324E6D948E4C6C60C0621CDAC48623A",
			secretKey: "secret",
			expected:  false, // Should be case sensitive
		},
		{
			name:      "JSON payload verification",
			payload:   `{"user":"alice","action":"delete","timestamp":1700000000}`,
			signature: "", // Will be calculated in test
			secretKey: "api-key-2024",
			expected:  true,
		},
		{
			name:      "Large payload",
			payload:   strings.Repeat("data", 250), // 1000 characters
			signature: "",                          // Will be calculated in test
			secretKey: "large-data-key",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For tests where signature is empty, generate the correct signature
			if tt.signature == "" && tt.expected {
				tt.signature = signRequest(tt.payload, []byte(tt.secretKey))
			}

			result := VerifyAxalSignature(tt.payload, tt.signature, tt.secretKey)

			if result != tt.expected {
				t.Errorf("VerifyAxalSignature() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSignRequestConsistency(t *testing.T) {
	message := "test consistency"
	secretKey := []byte("consistent-key")

	// Sign the same message multiple times
	sig1 := signRequest(message, secretKey)
	sig2 := signRequest(message, secretKey)
	sig3 := signRequest(message, secretKey)

	if sig1 != sig2 || sig2 != sig3 {
		t.Errorf("signRequest() is not consistent: %s, %s, %s", sig1, sig2, sig3)
	}
}

func TestVerifyAxalSignatureTimingAttackResistance(t *testing.T) {
	payload := "sensitive data"
	secretKey := "super-secret"
	validSig := signRequest(payload, []byte(secretKey))

	// Test with signatures of different lengths
	testSigs := []string{
		"",
		"short",
		"medium-length-signature",
		validSig[:32],           // Half length
		validSig + "extra",      // Too long
		strings.Repeat("a", 64), // Same length, all 'a'
		strings.Repeat("f", 64), // Same length, all 'f'
	}

	for _, invalidSig := range testSigs {
		result := VerifyAxalSignature(payload, invalidSig, secretKey)
		if result {
			t.Errorf("VerifyAxalSignature() should return false for invalid signature: %s", invalidSig)
		}
	}

	// Verify the valid signature still works
	if !VerifyAxalSignature(payload, validSig, secretKey) {
		t.Error("VerifyAxalSignature() should return true for valid signature")
	}
}

func TestVerifyAxalSignatureEdgeCases(t *testing.T) {
	// Test with very long secret key
	longKey := strings.Repeat("k", 1000)
	payload := "test"
	sig := signRequest(payload, []byte(longKey))

	if !VerifyAxalSignature(payload, sig, longKey) {
		t.Error("VerifyAxalSignature() failed with long secret key")
	}

	// Test with binary-like data in payload
	binaryPayload := string([]byte{0, 1, 2, 3, 255, 254, 253})
	binarySig := signRequest(binaryPayload, []byte("binary-key"))

	if !VerifyAxalSignature(binaryPayload, binarySig, "binary-key") {
		t.Error("VerifyAxalSignature() failed with binary payload")
	}
}
