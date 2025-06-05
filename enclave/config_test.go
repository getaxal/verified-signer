package enclave

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPortConfig_Success(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 8080
  privy_api_vsock_port: 9090
  router_vsock_port: 7070
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, uint32(8080), config.AWSSecretManagerVsockPort)
	assert.Equal(t, uint32(9090), config.PrivyAPIVsockPort)
	assert.Equal(t, uint32(7070), config.RouterVsockPort)
}

func TestLoadPortConfig_MaxPortValues(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 65535
  privy_api_vsock_port: 65534
  router_vsock_port: 65533
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, uint32(65535), config.AWSSecretManagerVsockPort)
	assert.Equal(t, uint32(65534), config.PrivyAPIVsockPort)
	assert.Equal(t, uint32(65533), config.RouterVsockPort)
}

func TestLoadPortConfig_ZeroAWSPort(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 0
  privy_api_vsock_port: 9090
  router_vsock_port: 7070
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_ZeroPrivyPort(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 8080
  privy_api_vsock_port: 0
  router_vsock_port: 7070
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_ZeroRouterPort(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 8080
  privy_api_vsock_port: 9090
  router_vsock_port: 0
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_AllZeroPorts(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 0
  privy_api_vsock_port: 0
  router_vsock_port: 0
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_MissingPortsSection(t *testing.T) {
	configContent := `
other_config:
  value: "test"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_MissingPortFields(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 8080
  # Missing other port fields
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_FileNotFound(t *testing.T) {
	config, err := LoadPortConfig("/non/existent/path.yaml")

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "no port loaded from")
}

func TestLoadPortConfig_InvalidYAML(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 8080
  privy_api_vsock_port: invalid_port
  router_vsock_port: 7070
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "failed to load config from")
}

func TestLoadPortConfig_MinimumValidPorts(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 1
  privy_api_vsock_port: 1
  router_vsock_port: 1
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, uint32(1), config.AWSSecretManagerVsockPort)
	assert.Equal(t, uint32(1), config.PrivyAPIVsockPort)
	assert.Equal(t, uint32(1), config.RouterVsockPort)
}

// ============= LoadVerifierConfig Tests =============

func TestLoadVerifierConfig_Success(t *testing.T) {
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "pool1.example.com"
    - "pool2.example.com"
    - "pool3.example.com"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Len(t, config.Whitelist.Pools, 3)
	assert.Contains(t, config.Whitelist.Pools, "pool1.example.com")
	assert.Contains(t, config.Whitelist.Pools, "pool2.example.com")
	assert.Contains(t, config.Whitelist.Pools, "pool3.example.com")
}

func TestLoadVerifierConfig_SinglePool(t *testing.T) {
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "single-pool.example.com"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Len(t, config.Whitelist.Pools, 1)
	assert.Equal(t, "single-pool.example.com", config.Whitelist.Pools[0])
}

func TestLoadVerifierConfig_EmptyPools(t *testing.T) {
	configContent := `
whitelist_config:
  whitelisted_pools: []
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "Failed to load verifier config")
}

func TestLoadVerifierConfig_MissingWhitelistSection(t *testing.T) {
	configContent := `
some_other_config:
  value: "test"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "Failed to load verifier config")
}

func TestLoadVerifierConfig_FileNotFound(t *testing.T) {
	config, err := LoadVerifierConfig("/non/existent/path.yaml")

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "Failed to load verifier config")
}

func TestLoadVerifierConfig_InvalidYAML(t *testing.T) {
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "pool1.example.com"
    - pool2.example.com  # Invalid YAML
      invalid: yaml
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "Failed to load verifier config")
}

func TestLoadVerifierConfig_InlineArrayFormat(t *testing.T) {
	configContent := `
whitelist_config:
  whitelisted_pools: ["pool1.com", "pool2.com", "pool3.com"]
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Len(t, config.Whitelist.Pools, 3)
	assert.Contains(t, config.Whitelist.Pools, "pool1.com")
	assert.Contains(t, config.Whitelist.Pools, "pool2.com")
	assert.Contains(t, config.Whitelist.Pools, "pool3.com")
}

// ============= Combined Config Tests =============

func TestCombinedConfig_BothPortsAndVerifier(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 8080
  privy_api_vsock_port: 9090
  router_vsock_port: 7070

whitelist_config:
  whitelisted_pools:
    - "pool1.example.com"
    - "pool2.example.com"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	// Test both functions work with the same file
	portConfig, portErr := LoadPortConfig(configPath)
	verifierConfig, verifierErr := LoadVerifierConfig(configPath)

	// Both should succeed
	require.NoError(t, portErr)
	require.NoError(t, verifierErr)
	require.NotNil(t, portConfig)
	require.NotNil(t, verifierConfig)

	// Verify port config
	assert.Equal(t, uint32(8080), portConfig.AWSSecretManagerVsockPort)
	assert.Equal(t, uint32(9090), portConfig.PrivyAPIVsockPort)
	assert.Equal(t, uint32(7070), portConfig.RouterVsockPort)

	// Verify verifier config
	assert.Len(t, verifierConfig.Whitelist.Pools, 2)
	assert.Contains(t, verifierConfig.Whitelist.Pools, "pool1.example.com")
	assert.Contains(t, verifierConfig.Whitelist.Pools, "pool2.example.com")
}

// ============= Table-Driven Tests =============

func TestLoadPortConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		configYAML     string
		expectError    bool
		expectedAWS    uint32
		expectedAPI    uint32
		expectedRouter uint32
	}{
		{
			name: "valid_standard_ports",
			configYAML: `
ports:
  aws_secret_manager_vsock_port: 8080
  privy_api_vsock_port: 9090
  router_vsock_port: 7070`,
			expectError:    false,
			expectedAWS:    8080,
			expectedAPI:    9090,
			expectedRouter: 7070,
		},
		{
			name: "valid_high_ports",
			configYAML: `
ports:
  aws_secret_manager_vsock_port: 50000
  privy_api_vsock_port: 60000
  router_vsock_port: 55000`,
			expectError:    false,
			expectedAWS:    50000,
			expectedAPI:    60000,
			expectedRouter: 55000,
		},
		{
			name: "zero_aws_port",
			configYAML: `
ports:
  aws_secret_manager_vsock_port: 0
  privy_api_vsock_port: 9090
  router_vsock_port: 7070`,
			expectError: true,
		},
		{
			name: "missing_ports_section",
			configYAML: `
other_config:
  value: "test"`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, tt.configYAML)
			defer os.Remove(configPath)

			config, err := LoadPortConfig(configPath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, config)
			} else {
				require.NoError(t, err)
				require.NotNil(t, config)
				assert.Equal(t, tt.expectedAWS, config.AWSSecretManagerVsockPort)
				assert.Equal(t, tt.expectedAPI, config.PrivyAPIVsockPort)
				assert.Equal(t, tt.expectedRouter, config.RouterVsockPort)
			}
		})
	}
}

func TestLoadVerifierConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		expectError bool
		expectPools int
	}{
		{
			name: "valid_multiple_pools",
			configYAML: `
whitelist_config:
  whitelisted_pools:
    - "pool1.example.com"
    - "pool2.example.com"
    - "pool3.example.com"`,
			expectError: false,
			expectPools: 3,
		},
		{
			name: "valid_single_pool",
			configYAML: `
whitelist_config:
  whitelisted_pools:
    - "single.pool.com"`,
			expectError: false,
			expectPools: 1,
		},
		{
			name: "empty_pools",
			configYAML: `
whitelist_config:
  whitelisted_pools: []`,
			expectError: true,
		},
		{
			name: "missing_whitelist_config",
			configYAML: `
other_config:
  value: "test"`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := createTempConfigFile(t, tt.configYAML)
			defer os.Remove(configPath)

			config, err := LoadVerifierConfig(configPath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, config)
			} else {
				require.NoError(t, err)
				require.NotNil(t, config)
				assert.Len(t, config.Whitelist.Pools, tt.expectPools)
			}
		})
	}
}

// ============= Helper Functions =============

func createTempConfigFile(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yaml")

	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	return configPath
}

// ============= Edge Case Tests =============

func TestLoadPortConfig_LargePortNumbers(t *testing.T) {
	configContent := `
ports:
  aws_secret_manager_vsock_port: 4294967295  # Max uint32
  privy_api_vsock_port: 4294967294
  router_vsock_port: 4294967293
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadPortConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, uint32(4294967295), config.AWSSecretManagerVsockPort)
	assert.Equal(t, uint32(4294967294), config.PrivyAPIVsockPort)
	assert.Equal(t, uint32(4294967293), config.RouterVsockPort)
}

func TestLoadVerifierConfig_SpecialCharactersInPools(t *testing.T) {
	configContent := `
whitelist_config:
  whitelisted_pools:
    - "pool-with-dashes.example.com"
    - "pool_with_underscores.example.com"
    - "pool123.with-numbers456.com"
    - "sub.domain.pool.example.com"
`
	configPath := createTempConfigFile(t, configContent)
	defer os.Remove(configPath)

	config, err := LoadVerifierConfig(configPath)

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Len(t, config.Whitelist.Pools, 4)
	assert.Contains(t, config.Whitelist.Pools, "pool-with-dashes.example.com")
	assert.Contains(t, config.Whitelist.Pools, "pool_with_underscores.example.com")
	assert.Contains(t, config.Whitelist.Pools, "pool123.with-numbers456.com")
	assert.Contains(t, config.Whitelist.Pools, "sub.domain.pool.example.com")
}
