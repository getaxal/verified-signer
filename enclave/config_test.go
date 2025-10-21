package enclave

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTEEConfig(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		configYAML  string
		filename    string
		wantErr     bool
		errContains string
		want        *TEEConfig
	}{
		{
			name: "valid config",
			configYAML: `
environment: "prod"
ports:
  aws_secret_manager_vsock_port: 8001
  privy_api_vsock_port: 8002
  router_vsock_port: 8003
  ec2_creds_vsock_port: 8004
`,
			filename: "valid_config.yaml",
			wantErr:  false,
			want: &TEEConfig{
				Environment: "prod",
				Ports: PortConfig{
					AWSSecretManagerVsockPort: 8001,
					PrivyAPIVsockPort:         8002,
					RouterVsockPort:           8003,
					Ec2CredsVsockPort:         8004,
				},
			},
		},
		{
			name: "valid config with dev environment",
			configYAML: `
environment: "dev"
ports:
  aws_secret_manager_vsock_port: 9001
  privy_api_vsock_port: 9002
  router_vsock_port: 9003
  ec2_creds_vsock_port: 9004
`,
			filename: "dev_config.yaml",
			wantErr:  false,
			want: &TEEConfig{
				Environment: "dev",
				Ports: PortConfig{
					AWSSecretManagerVsockPort: 9001,
					PrivyAPIVsockPort:         9002,
					RouterVsockPort:           9003,
					Ec2CredsVsockPort:         9004,
				},
			},
		},
		{
			name: "missing environment",
			configYAML: `
ports:
  aws_secret_manager_vsock_port: 8001
  privy_api_vsock_port: 8002
  router_vsock_port: 8003
  ec2_creds_vsock_port: 8004
`,
			filename:    "no_env_config.yaml",
			wantErr:     true,
			errContains: "no env loaded from",
		},
		{
			name: "missing AWS port",
			configYAML: `
environment: "prod"
ports:
  privy_api_vsock_port: 8002
  router_vsock_port: 8003
  ec2_creds_vsock_port: 8004
`,
			filename:    "no_aws_port_config.yaml",
			wantErr:     true,
			errContains: "no port loaded from",
		},
		{
			name: "missing Privy API port",
			configYAML: `
environment: "prod"
ports:
  aws_secret_manager_vsock_port: 8001
  router_vsock_port: 8003
  ec2_creds_vsock_port: 8004
`,
			filename:    "no_privy_port_config.yaml",
			wantErr:     true,
			errContains: "no port loaded from",
		},
		{
			name: "missing Router port",
			configYAML: `
environment: "prod"
ports:
  aws_secret_manager_vsock_port: 8001
  privy_api_vsock_port: 8002
  ec2_creds_vsock_port: 8004
`,
			filename:    "no_router_port_config.yaml",
			wantErr:     true,
			errContains: "no port loaded from",
		},
		{
			name: "zero AWS port value",
			configYAML: `
environment: "prod"
ports:
  aws_secret_manager_vsock_port: 0
  privy_api_vsock_port: 8002
  router_vsock_port: 8003
  ec2_creds_vsock_port: 8004
`,
			filename:    "zero_aws_port_config.yaml",
			wantErr:     true,
			errContains: "no port loaded from",
		},
		{
			name: "empty environment string",
			configYAML: `
environment: ""
ports:
  aws_secret_manager_vsock_port: 8001
  privy_api_vsock_port: 8002
  router_vsock_port: 8003
  ec2_creds_vsock_port: 8004
`,
			filename:    "empty_env_config.yaml",
			wantErr:     true,
			errContains: "no env loaded from",
		},
		{
			name: "EC2 creds port can be zero (not validated)",
			configYAML: `
environment: "local"
ports:
  aws_secret_manager_vsock_port: 8001
  privy_api_vsock_port: 8002
  router_vsock_port: 8003
  ec2_creds_vsock_port: 0
`,
			filename: "zero_ec2_port_config.yaml",
			wantErr:  false,
			want: &TEEConfig{
				Environment: "local",
				Ports: PortConfig{
					AWSSecretManagerVsockPort: 8001,
					PrivyAPIVsockPort:         8002,
					RouterVsockPort:           8003,
					Ec2CredsVsockPort:         0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test config file
			configPath := filepath.Join(tmpDir, tt.filename)
			err := os.WriteFile(configPath, []byte(tt.configYAML), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			// Test LoadTEEConfig
			got, err := LoadTEEConfig(configPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadTEEConfig() expected error but got none")
					return
				}
				if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("LoadTEEConfig() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("LoadTEEConfig() unexpected error = %v", err)
				return
			}

			// Compare results
			if got.Environment != tt.want.Environment {
				t.Errorf("LoadTEEConfig() Environment = %v, want %v", got.Environment, tt.want.Environment)
			}
			if got.Ports.AWSSecretManagerVsockPort != tt.want.Ports.AWSSecretManagerVsockPort {
				t.Errorf("LoadTEEConfig() AWSSecretManagerVsockPort = %v, want %v",
					got.Ports.AWSSecretManagerVsockPort, tt.want.Ports.AWSSecretManagerVsockPort)
			}
			if got.Ports.PrivyAPIVsockPort != tt.want.Ports.PrivyAPIVsockPort {
				t.Errorf("LoadTEEConfig() PrivyAPIVsockPort = %v, want %v",
					got.Ports.PrivyAPIVsockPort, tt.want.Ports.PrivyAPIVsockPort)
			}
			if got.Ports.RouterVsockPort != tt.want.Ports.RouterVsockPort {
				t.Errorf("LoadTEEConfig() RouterVsockPort = %v, want %v",
					got.Ports.RouterVsockPort, tt.want.Ports.RouterVsockPort)
			}
			if got.Ports.Ec2CredsVsockPort != tt.want.Ports.Ec2CredsVsockPort {
				t.Errorf("LoadTEEConfig() Ec2CredsVsockPort = %v, want %v",
					got.Ports.Ec2CredsVsockPort, tt.want.Ports.Ec2CredsVsockPort)
			}
		})
	}
}

func TestLoadTEEConfig_FileNotFound(t *testing.T) {
	nonExistentPath := "/path/that/does/not/exist/config.yaml"

	_, err := LoadTEEConfig(nonExistentPath)

	if err == nil {
		t.Error("LoadTEEConfig() expected error for non-existent file but got none")
	}

	if !containsString(err.Error(), "failed to load config from") {
		t.Errorf("LoadTEEConfig() error = %v, want error containing 'failed to load config from'", err)
	}
}

func TestLoadTEEConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Create invalid YAML file
	invalidYAML := `
environment: "prod"
ports:
  aws_secret_manager_vsock_port: 8001
  privy_api_vsock_port: [invalid yaml structure
`
	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = LoadTEEConfig(configPath)

	if err == nil {
		t.Error("LoadTEEConfig() expected error for invalid YAML but got none")
	}

	if !containsString(err.Error(), "failed to load config from") {
		t.Errorf("LoadTEEConfig() error = %v, want error containing 'failed to load config from'", err)
	}
}

func TestTEEConfig_GetEnv(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		want        string
	}{
		{
			name:        "prod environment",
			environment: "prod",
			want:        "prod",
		},
		{
			name:        "dev environment",
			environment: "dev",
			want:        "dev",
		},
		{
			name:        "local environment",
			environment: "local",
			want:        "local",
		},
		{
			name:        "staging environment",
			environment: "staging",
			want:        "staging",
		},
		{
			name:        "invalid environment defaults to local",
			environment: "invalid",
			want:        "local",
		},
		{
			name:        "empty environment defaults to local",
			environment: "",
			want:        "local",
		},
		{
			name:        "test environment defaults to local",
			environment: "test",
			want:        "local",
		},
		{
			name:        "production environment defaults to local",
			environment: "production",
			want:        "local",
		},
		{
			name:        "case sensitive - PROD defaults to local",
			environment: "PROD",
			want:        "local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &TEEConfig{
				Environment: tt.environment,
				Ports: PortConfig{
					AWSSecretManagerVsockPort: 8001,
					PrivyAPIVsockPort:         8002,
					RouterVsockPort:           8003,
					Ec2CredsVsockPort:         8004,
				},
			}

			if got := cfg.GetEnv(); got != tt.want {
				t.Errorf("TEEConfig.GetEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTEEConfig_GetEnv_NilConfig(t *testing.T) {
	// Test behavior with nil config (should panic or handle gracefully)
	// This test documents current behavior - adjust based on desired behavior
	defer func() {
		if r := recover(); r == nil {
			t.Error("TEEConfig.GetEnv() on nil config should have panicked")
		}
	}()

	var cfg *TEEConfig
	cfg.GetEnv()
}

func TestPortConfig_DefaultValues(t *testing.T) {
	// Test that PortConfig fields have correct zero values
	var ports PortConfig

	if ports.AWSSecretManagerVsockPort != 0 {
		t.Errorf("PortConfig.AWSSecretManagerVsockPort default = %v, want 0", ports.AWSSecretManagerVsockPort)
	}
	if ports.PrivyAPIVsockPort != 0 {
		t.Errorf("PortConfig.PrivyAPIVsockPort default = %v, want 0", ports.PrivyAPIVsockPort)
	}
	if ports.RouterVsockPort != 0 {
		t.Errorf("PortConfig.RouterVsockPort default = %v, want 0", ports.RouterVsockPort)
	}
	if ports.Ec2CredsVsockPort != 0 {
		t.Errorf("PortConfig.Ec2CredsVsockPort default = %v, want 0", ports.Ec2CredsVsockPort)
	}
}

func TestTEEConfig_DefaultValues(t *testing.T) {
	// Test that TEEConfig fields have correct zero values
	var config TEEConfig

	if config.Environment != "" {
		t.Errorf("TEEConfig.Environment default = %v, want empty string", config.Environment)
	}

	// Test that embedded PortConfig also has zero values
	if config.Ports.AWSSecretManagerVsockPort != 0 {
		t.Errorf("TEEConfig.Ports.AWSSecretManagerVsockPort default = %v, want 0",
			config.Ports.AWSSecretManagerVsockPort)
	}
}

// Helper function to check if a string contains another string
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
