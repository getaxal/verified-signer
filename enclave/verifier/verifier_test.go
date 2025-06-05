package verifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	data "github.com/getaxal/verified-signer/enclave/privy-signer/data"
)

// ============= Mock EthTxRequest for testing =============

type MockEthTxRequest struct {
	mock.Mock
}

func (m *MockEthTxRequest) ValidateTxRequest() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockEthTxRequest) GetMethod() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockEthTxRequest) GetTransaction() *data.EthTransaction {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*data.EthTransaction)
}

// ============= InitVerifierFromVerifierConfig Tests =============

func TestInitVerifierFromVerifierConfig_Success(t *testing.T) {
	// Create a valid config file
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
    - "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Test successful initialization
	verifier, err := InitVerifieFromVerifierConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, verifier)
	require.NotNil(t, verifier.verifiedAddresses)
}

func TestInitVerifierFromVerifierConfig_InvalidPath(t *testing.T) {
	// Test with non-existent file path
	verifier, err := InitVerifieFromVerifierConfig("/non/existent/path.yaml")

	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "Unable to init verifier")
}

func TestInitVerifierFromVerifierConfig_InvalidConfig(t *testing.T) {
	// Create an invalid config file (empty pools)
	configContent := `
whitelist_config:
  whitelisted_pools: []
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	verifier, err := InitVerifieFromVerifierConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "Unable to init verifier")
}

func TestInitVerifierFromVerifierConfig_MalformedYAML(t *testing.T) {
	// Create a malformed YAML file
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "pool1.example.com"
    - pool2.example.com  # Invalid YAML
      invalid: yaml
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	verifier, err := InitVerifieFromVerifierConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "Unable to init verifier")
}

// ============= VerifyEthTxRequest Integration Tests =============
// Note: These tests require a working WhiteList implementation
// If InitWhitelistFromConfig and WhiteList.IsWhitelisted work correctly

func TestVerifier_VerifyEthTxRequest_EthSignTransaction_Integration(t *testing.T) {
	// Create config with whitelisted address
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
    - "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Initialize verifier
	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	// Test whitelisted address
	mockRequest := &MockEthTxRequest{}
	mockTransaction := &data.EthTransaction{
		To: "0x1234567890123456789012345678901234567890",
	}

	mockRequest.On("GetMethod").Return("eth_signTransaction")
	mockRequest.On("GetTransaction").Return(mockTransaction)

	result := verifier.VerifyEthTxRequest(mockRequest)
	assert.True(t, result)
	mockRequest.AssertExpectations(t)

	// Test non-whitelisted address
	mockRequest2 := &MockEthTxRequest{}
	mockTransaction2 := &data.EthTransaction{
		To: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}

	mockRequest2.On("GetMethod").Return("eth_signTransaction")
	mockRequest2.On("GetTransaction").Return(mockTransaction2)

	result2 := verifier.VerifyEthTxRequest(mockRequest2)
	assert.False(t, result2)
	mockRequest2.AssertExpectations(t)
}

func TestVerifier_VerifyEthTxRequest_EthSendTransaction_Integration(t *testing.T) {
	// Create config with whitelisted address
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Initialize verifier
	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	// Test whitelisted address
	mockRequest := &MockEthTxRequest{}
	mockTransaction := &data.EthTransaction{
		To: "0x1234567890123456789012345678901234567890",
	}

	mockRequest.On("GetMethod").Return("eth_sendTransaction")
	mockRequest.On("GetTransaction").Return(mockTransaction)

	result := verifier.VerifyEthTxRequest(mockRequest)
	assert.True(t, result)
	mockRequest.AssertExpectations(t)
}

func TestVerifier_VerifyEthTxRequest_PersonalSign_NilTransaction(t *testing.T) {
	// Create any valid config
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Initialize verifier
	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	mockRequest := &MockEthTxRequest{}
	mockRequest.On("GetMethod").Return("personal_sign")
	mockRequest.On("GetTransaction").Return(nil)

	result := verifier.VerifyEthTxRequest(mockRequest)
	assert.True(t, result)
	mockRequest.AssertExpectations(t)
}

func TestVerifier_VerifyEthTxRequest_PersonalSign_WithTransaction(t *testing.T) {
	// Create any valid config
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Initialize verifier
	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	mockRequest := &MockEthTxRequest{}
	mockTransaction := &data.EthTransaction{
		To: "0x1234567890123456789012345678901234567890",
	}

	mockRequest.On("GetMethod").Return("personal_sign")
	mockRequest.On("GetTransaction").Return(mockTransaction)

	result := verifier.VerifyEthTxRequest(mockRequest)
	assert.False(t, result)
	mockRequest.AssertExpectations(t)
}

func TestVerifier_VerifyEthTxRequest_UnknownMethod(t *testing.T) {
	// Create any valid config
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Initialize verifier
	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	mockRequest := &MockEthTxRequest{}
	mockRequest.On("GetMethod").Return("unknown_method")

	result := verifier.VerifyEthTxRequest(mockRequest)
	assert.False(t, result)
	mockRequest.AssertExpectations(t)
}

// ============= Table-Driven Tests =============

func TestInitVerifierFromVerifierConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		setupFile   bool
		expectError bool
	}{
		{
			name: "valid_single_pool",
			configYAML: `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"`,
			setupFile:   true,
			expectError: false,
		},
		{
			name: "valid_multiple_pools",
			configYAML: `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
    - "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    - "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"`,
			setupFile:   true,
			expectError: false,
		},
		{
			name: "empty_pools",
			configYAML: `
whitelist_config:
  whitelisted_pools: []`,
			setupFile:   true,
			expectError: true,
		},
		{
			name: "missing_whitelist_config",
			configYAML: `
other_config:
  value: "test"`,
			setupFile:   true,
			expectError: true,
		},
		{
			name:        "file_not_found",
			configYAML:  "", // Not used
			setupFile:   false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var configPath string

			if tt.setupFile {
				configPath = createTempConfigFile(t, tt.configYAML)
				defer os.Remove(configPath)
			} else {
				configPath = "/non/existent/path.yaml"
			}

			verifier, err := InitVerifieFromVerifierConfig(configPath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, verifier)
				assert.Contains(t, err.Error(), "Unable to init verifier")
			} else {
				require.NoError(t, err)
				require.NotNil(t, verifier)
				require.NotNil(t, verifier.verifiedAddresses)
			}
		})
	}
}

func TestVerifier_VerifyEthTxRequest_TableDriven(t *testing.T) {
	// Create config with known whitelisted addresses
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
    - "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Initialize verifier
	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		transaction    *data.EthTransaction
		expectedResult bool
	}{
		{
			name:   "eth_signTransaction_whitelisted",
			method: "eth_signTransaction",
			transaction: &data.EthTransaction{
				To: "0x1234567890123456789012345678901234567890",
			},
			expectedResult: true,
		},
		{
			name:   "eth_signTransaction_not_whitelisted",
			method: "eth_signTransaction",
			transaction: &data.EthTransaction{
				To: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			expectedResult: false,
		},
		{
			name:   "eth_sendTransaction_whitelisted",
			method: "eth_sendTransaction",
			transaction: &data.EthTransaction{
				To: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			},
			expectedResult: true,
		},
		{
			name:   "eth_sendTransaction_not_whitelisted",
			method: "eth_sendTransaction",
			transaction: &data.EthTransaction{
				To: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
			expectedResult: false,
		},
		{
			name:           "personal_sign_nil_transaction",
			method:         "personal_sign",
			transaction:    nil,
			expectedResult: true,
		},
		{
			name:   "personal_sign_with_transaction",
			method: "personal_sign",
			transaction: &data.EthTransaction{
				To: "0x1234567890123456789012345678901234567890",
			},
			expectedResult: false,
		},
		{
			name:           "unknown_method",
			method:         "unknown_method",
			transaction:    nil,
			expectedResult: false,
		},
		{
			name:           "empty_method",
			method:         "",
			transaction:    nil,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRequest := &MockEthTxRequest{}

			mockRequest.On("GetMethod").Return(tt.method)
			if tt.method == "eth_signTransaction" || tt.method == "eth_sendTransaction" || tt.method == "personal_sign" {
				mockRequest.On("GetTransaction").Return(tt.transaction)
			}

			result := verifier.VerifyEthTxRequest(mockRequest)

			assert.Equal(t, tt.expectedResult, result)
			mockRequest.AssertExpectations(t)
		})
	}
}

// ============= Edge Case Tests =============

func TestVerifier_VerifyEthTxRequest_EmptyToAddress(t *testing.T) {
	// Create config
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "0x1234567890123456789012345678901234567890"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	verifier, err := InitVerifieFromVerifierConfig(configPath)
	require.NoError(t, err)

	mockRequest := &MockEthTxRequest{}
	mockTransaction := &data.EthTransaction{
		To: "", // Empty address
	}

	mockRequest.On("GetMethod").Return("eth_signTransaction")
	mockRequest.On("GetTransaction").Return(mockTransaction)

	result := verifier.VerifyEthTxRequest(mockRequest)
	assert.False(t, result)
	mockRequest.AssertExpectations(t)
}

// ============= Helper Functions =============

func createTempConfigFile(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yaml")

	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	return configPath
}
