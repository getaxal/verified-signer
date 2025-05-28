package aws

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestNewAWSConfigFromYAML_Success(t *testing.T) {
	// Create a temporary YAML config file
	configContent := `
aws_credentials:
  access_key: AKIAIOSFODNN7EXAMPLE
  access_secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up

	// Write config content
	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test the function
	config, err := NewAWSConfigFromYAML(tmpFile.Name())

	// Assertions
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if config == nil {
		t.Fatal("Expected config to not be nil")
	}

	if config.AWSCredentials.AccessKey != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Expected AccessKey to be 'AKIAIOSFODNN7EXAMPLE', got: %s", config.AWSCredentials.AccessKey)
	}

	if config.AWSCredentials.AccessSecret != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("Expected AccessSecret to be 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', got: %s", config.AWSCredentials.AccessSecret)
	}
}

func TestNewAWSConfigFromYAML_FileNotFound(t *testing.T) {
	// Test with non-existent file
	config, err := NewAWSConfigFromYAML("non_existent_file.yaml")

	// Assertions
	if err == nil {
		t.Error("Expected an error for non-existent file, got nil")
	}

	if config != nil {
		t.Error("Expected config to be nil when file doesn't exist")
	}

	// Check error message contains expected text
	expectedErrText := "could not fetch aws credentials from config file at"
	fmt.Print(err)
	if err != nil && !strings.Contains(err.Error(), expectedErrText) {
		t.Errorf("Expected error to contain '%s', got: %s", expectedErrText, err.Error())
	}
}

func TestNewAWSConfigFromYAML_InvalidYAML(t *testing.T) {
	// Create a temporary file with invalid YAML
	invalidYAML := `
credentials:
  access_key: AKIAIOSFODNN7EXAMPLE
  access_secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    invalid_indentation: true
`

	tmpFile, err := os.CreateTemp("", "test_invalid_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(invalidYAML); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test the function
	config, err := NewAWSConfigFromYAML(tmpFile.Name())

	// Assertions
	if err == nil {
		t.Error("Expected an error for invalid YAML, got nil")
	}

	if config != nil {
		t.Error("Expected config to be nil when YAML is invalid")
	}
}

func TestNewAWSConfigFromYAML_MissingAccessKey(t *testing.T) {
	// Create config with missing access_key
	configContent := `
credentials:
  access_secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`

	tmpFile, err := os.CreateTemp("", "test_missing_key_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test the function
	config, err := NewAWSConfigFromYAML(tmpFile.Name())

	// Assertions
	if err == nil {
		t.Error("Expected an error for missing access_key, got nil")
	}

	if config != nil {
		t.Error("Expected config to be nil when access_key is missing")
	}

	expectedErrText := "could not fetch aws credentials from config file"
	if err != nil && !strings.Contains(err.Error(), expectedErrText) {
		t.Errorf("Expected error to contain '%s', got: %s", expectedErrText, err.Error())
	}
}

func TestNewAWSConfigFromYAML_MissingAccessSecret(t *testing.T) {
	// Create config with missing access_secret
	configContent := `
credentials:
  access_key: AKIAIOSFODNN7EXAMPLE
`

	tmpFile, err := os.CreateTemp("", "test_missing_secret_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test the function
	config, err := NewAWSConfigFromYAML(tmpFile.Name())

	// Assertions
	if err == nil {
		t.Error("Expected an error for missing access_secret, got nil")
	}

	if config != nil {
		t.Error("Expected config to be nil when access_secret is missing")
	}

	expectedErrText := "could not fetch aws credentials from config file"
	if err != nil && !strings.Contains(err.Error(), expectedErrText) {
		t.Errorf("Expected error to contain '%s', got: %s", expectedErrText, err.Error())
	}
}

func TestNewAWSConfigFromYAML_EmptyCredentials(t *testing.T) {
	// Create config with empty credentials
	configContent := `
credentials:
  access_key: ""
  access_secret: ""
`

	tmpFile, err := os.CreateTemp("", "test_empty_creds_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test the function
	config, err := NewAWSConfigFromYAML(tmpFile.Name())

	// Assertions
	if err == nil {
		t.Error("Expected an error for empty credentials, got nil")
	}

	if config != nil {
		t.Error("Expected config to be nil when credentials are empty")
	}
}
