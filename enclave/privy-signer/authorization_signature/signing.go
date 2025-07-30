package authorizationsignature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"unsafe"

	"github.com/awnumar/memguard"
)

func init() {
	// Initialize memguard session and setup interrupt handling
	memguard.CatchInterrupt()
}

// secureMemory provides memory that's protected from swapping and cleared properly
type secureMemory struct {
	buffer *memguard.LockedBuffer
}

// newSecureMemory creates protected memory using memguard
func newSecureMemory(size int) *secureMemory {
	buffer := memguard.NewBuffer(size)
	return &secureMemory{buffer: buffer}
}

// newSecureMemoryFromData creates protected memory from existing data
func newSecureMemoryFromData(data []byte) *secureMemory {
	// Create a copy of the data first since NewBufferFromBytes wipes the source
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	buffer := memguard.NewBufferFromBytes(dataCopy)
	return &secureMemory{buffer: buffer}
}

// bytes returns access to the protected memory
func (sm *secureMemory) bytes() []byte {
	return sm.buffer.Bytes()
}

// destroy securely destroys the protected memory
func (sm *secureMemory) destroy() {
	if sm.buffer != nil {
		sm.buffer.Destroy()
	}
}

// secureZero uses a compiler barrier to prevent optimization
func secureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Use volatile operations that the compiler cannot optimize away
	ptr := unsafe.Pointer(&data[0])
	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Add(ptr, i)) = 0
	}
}

// parsePrivateKeyFromAuthorizationKeyBytes parses the ecdsa key from authorization key bytes
func parsePrivateKeyFromAuthorizationKeyBytes(authKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	authMem := newSecureMemoryFromData(authKeyBytes)
	defer authMem.destroy()

	authData := authMem.bytes()

	// Find and extract the base64 portion
	prefix := []byte("wallet-auth:")
	var pkcs8B64Bytes []byte

	if bytes.HasPrefix(authData, prefix) {
		pkcs8B64Bytes = authData[len(prefix):]
	} else {
		pkcs8B64Bytes = authData
	}

	// Create secure memory for base64 data
	b64Mem := newSecureMemoryFromData(pkcs8B64Bytes)
	defer b64Mem.destroy()

	b64Data := b64Mem.bytes()

	// Decode and parse
	decodedSize := base64.StdEncoding.DecodedLen(len(b64Data))
	pkcs8Mem := newSecureMemory(decodedSize)
	defer pkcs8Mem.destroy()

	pkcs8Data := pkcs8Mem.bytes()

	actualSize, err := base64.StdEncoding.Decode(pkcs8Data, b64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS8 key: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(pkcs8Data[:actualSize])
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key provided is not an ECDSA private key")
	}

	return ecdsaKey, nil
}

// SignPayload signs the canonicalized JSON payload using ECDSA (P-256 + SHA-256)
func SignPayload(privyAuthorizationKeyBytes, payloadBytes []byte) ([]byte, error) {
	// Parse private key first
	privateKey, err := parsePrivateKeyFromAuthorizationKeyBytes(privyAuthorizationKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	payloadMem := newSecureMemoryFromData(payloadBytes)
	defer payloadMem.destroy()

	payloadData := payloadMem.bytes()

	// Create secure memory for hash computation
	hashMem := newSecureMemory(sha256.Size)
	defer hashMem.destroy()

	// Hash the payload directly into secure memory
	hasher := sha256.New()
	hasher.Write(payloadData)
	hashBytes := hasher.Sum(nil)
	copy(hashMem.bytes(), hashBytes)
	secureZero(hashBytes) // Clear the temporary hash

	// Sign the hash from secure memory
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashMem.bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}
	defer secureZero(signature)

	// Encode to base64
	result := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
	base64.StdEncoding.Encode(result, signature)

	return result, nil
}

// VerifySignature verifies signature with all byte slice inputs
func VerifySignature(publicKey *ecdsa.PublicKey, payloadBytes, signatureB64Bytes []byte) (bool, error) {
	payloadMem := newSecureMemoryFromData(payloadBytes)
	defer payloadMem.destroy()

	sigMem := newSecureMemoryFromData(signatureB64Bytes)
	defer sigMem.destroy()

	payloadData := payloadMem.bytes()
	sigData := sigMem.bytes()

	// Create secure memory for decoded signature
	sigSize := base64.StdEncoding.DecodedLen(len(sigData))
	sigBytesMem := newSecureMemory(sigSize)
	defer sigBytesMem.destroy()

	actualSigSize, err := base64.StdEncoding.Decode(sigBytesMem.bytes(), sigData)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create secure memory for hash computation
	hashMem := newSecureMemory(sha256.Size)
	defer hashMem.destroy()

	// Hash the payload directly into secure memory
	hasher := sha256.New()
	hasher.Write(payloadData)
	hashBytes := hasher.Sum(nil)
	copy(hashMem.bytes(), hashBytes)
	secureZero(hashBytes) // Clear the temporary hash

	// Verify signature using data from secure memories
	valid := ecdsa.VerifyASN1(publicKey, hashMem.bytes(), sigBytesMem.bytes()[:actualSigSize])
	return valid, nil
}

// SecureCompare performs constant-time comparison to prevent timing attacks
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
