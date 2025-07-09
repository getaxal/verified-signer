package privysigner

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
)

// RoundTripFunc is a function type that implements http.RoundTripper
type RoundTripFunc func(req *http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// Helper function to create a mock HTTP client with custom transport
func createMockClient(roundTripFunc RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: roundTripFunc,
	}
}

// Helper function to create a test PrivyClient
func createTestPrivyClient(httpClient *http.Client) *PrivyClient {
	return &PrivyClient{
		client:    httpClient,
		baseUrl:   "https://api.privy.io",
		userCache: ttlcache.New(ttlcache.WithTTL[string, data.PrivyUser](time.Hour)),
		privyConfig: &PrivyConfig{
			DelegatedActionsKeyId: "test-key-id",
		},
	}
}

func TestGetUser_CacheHit(t *testing.T) {
	// Create a mock client that shouldn't be called
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		t.Fatal("HTTP client should not be called when cache hit occurs")
		return nil, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	// Pre-populate cache
	cachedUser := data.PrivyUser{
		PrivyID: "test-user-id",
		LinkedAccounts: []data.LinkedAccount{
			{
				Address:   "0x123",
				ChainType: "ethereum",
				Delegated: true,
			},
		},
	}
	privyClient.userCache.Set("test-user-id", cachedUser, ttlcache.DefaultTTL)

	// Test
	result, err := privyClient.GetUser("test-user-id")

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-user-id", result.PrivyID)
	assert.Equal(t, "0x123", result.LinkedAccounts[0].Address)
}

func TestGetUser_Success_WithExistingWallet(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		// Verify the request
		assert.Equal(t, "GET", req.Method)
		assert.Contains(t, req.URL.String(), "test-user-id")

		// Mock response with user that has delegated wallet
		responseBody := `{
			"id": "test-user-id",
			"linked_accounts": [
				{
					"address": "0x123",
					"chain_type": "ethereum",
					"delegated": true
				}
			]
		}`

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
			Header:     make(http.Header),
		}, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	// Test
	result, err := privyClient.GetUser("test-user-id")

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-user-id", result.PrivyID)
	assert.Len(t, result.LinkedAccounts, 1)
	assert.Equal(t, "0x123", result.LinkedAccounts[0].Address)
	assert.True(t, result.LinkedAccounts[0].Delegated)
}

func TestGetUser_Success_CreatesWalletWhenNoneExists(t *testing.T) {
	callCount := 0
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		callCount++

		switch callCount {
		case 1:
			// First call - GET user without wallet
			assert.Equal(t, "GET", req.Method)
			assert.Contains(t, req.URL.String(), "test-user-id")

			responseBody := `{
				"id": "test-user-id",
				"linked_accounts": []
			}`

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
				Header:     make(http.Header),
			}, nil

		case 2:
			// Second call - POST create wallet
			assert.Equal(t, "POST", req.Method)
			assert.Contains(t, req.URL.String(), "test-user-id")

			responseBody := `{
				"linked_accounts": [
					{
						"address": "0x456",
						"chain_type": "ethereum",
						"delegated": true
					}
				]
			}`

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
				Header:     make(http.Header),
			}, nil

		default:
			t.Fatalf("Unexpected call count: %d", callCount)
			return nil, nil
		}
	})

	privyClient := createTestPrivyClient(mockClient)

	// Test
	result, err := privyClient.GetUser("test-user-id")

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-user-id", result.PrivyID)
	assert.Len(t, result.LinkedAccounts, 1)
	assert.Equal(t, "0x456", result.LinkedAccounts[0].Address)
	assert.True(t, result.LinkedAccounts[0].Delegated)
	assert.Equal(t, 2, callCount)
}

func TestGetUser_ErrorOnInitialRequest(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network error")
	})

	privyClient := createTestPrivyClient(mockClient)

	// Test
	result, err := privyClient.GetUser("test-user-id")

	// Assertions
	assert.Nil(t, result)
	assert.NotNil(t, err)
	assert.Equal(t, 500, err.Code)
	assert.Equal(t, "Internal Server Error", err.Message.Message)
}

func TestGetUser_ErrorOnNon200Status(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(bytes.NewBufferString(`{"error": "user not found"}`)),
			Header:     make(http.Header),
		}, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	// Test
	result, err := privyClient.GetUser("test-user-id")

	// Assertions
	assert.Nil(t, result)
	assert.NotNil(t, err)
	// The exact error depends on your handlePrivyError implementation
}

func TestGetUser_ErrorOnInvalidJSON(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(`invalid json`)),
			Header:     make(http.Header),
		}, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	// Test
	result, err := privyClient.GetUser("test-user-id")

	// Assertions
	assert.Nil(t, result)
	assert.NotNil(t, err)
	assert.Equal(t, 500, err.Code)
	assert.Equal(t, "Internal Server Error", err.Message.Message)
}

func TestCreateUserWalletsIfNotExists_WalletAlreadyExists(t *testing.T) {
	// This test doesn't need HTTP mocking since it should return early
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		t.Fatal("HTTP client should not be called when wallet already exists")
		return nil, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	user := data.PrivyUser{
		PrivyID: "test-user-id",
		LinkedAccounts: []data.LinkedAccount{
			{
				Address:   "0x123",
				ChainType: "ethereum",
				Delegated: true,
			},
		},
	}

	// Test
	result, err := privyClient.createUserWalletsIfNotExists(user, "test-user-id")

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-user-id", result.PrivyID)
	assert.Len(t, result.LinkedAccounts, 1)
}

func TestCreateUserWalletsIfNotExists_CreateWalletSuccess(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		// Verify the request
		assert.Equal(t, "POST", req.Method)
		assert.Contains(t, req.URL.String(), "test-user-id")

		responseBody := `{
			"linked_accounts": [
				{
					"address": "0x789",
					"chain_type": "ethereum",
					"delegated": true
				}
			]
		}`

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
			Header:     make(http.Header),
		}, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	user := data.PrivyUser{
		PrivyID:        "test-user-id",
		LinkedAccounts: []data.LinkedAccount{}, // No existing wallet
	}

	// Test
	result, err := privyClient.createUserWalletsIfNotExists(user, "test-user-id")

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-user-id", result.PrivyID)
	assert.Len(t, result.LinkedAccounts, 1)
	assert.Equal(t, "0x789", result.LinkedAccounts[0].Address)
	assert.True(t, result.LinkedAccounts[0].Delegated)
}

func TestCreateUserWalletsIfNotExists_CreateWalletError(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewBufferString(`{"error": "wallet creation failed"}`)),
			Header:     make(http.Header),
		}, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	user := data.PrivyUser{
		PrivyID:        "test-user-id",
		LinkedAccounts: []data.LinkedAccount{}, // No existing wallet
	}

	// Test
	result, err := privyClient.createUserWalletsIfNotExists(user, "test-user-id")

	// Assertions
	assert.Nil(t, result)
	assert.NotNil(t, err)
	// The exact error depends on your handlePrivyError implementation
}

func TestCreateUserWalletsIfNotExists_NoEthereumWalletInResponse(t *testing.T) {
	mockClient := createMockClient(func(req *http.Request) (*http.Response, error) {
		// Return response without ethereum delegated wallet
		responseBody := `{
			"linked_accounts": [
				{
					"address": "0x789",
					"chain_type": "solana",
					"delegated": true
				}
			]
		}`

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
			Header:     make(http.Header),
		}, nil
	})

	privyClient := createTestPrivyClient(mockClient)

	user := data.PrivyUser{
		PrivyID:        "test-user-id",
		LinkedAccounts: []data.LinkedAccount{},
	}

	// Test
	result, err := privyClient.createUserWalletsIfNotExists(user, "test-user-id")

	// Assertions
	assert.Nil(t, result)
	assert.NotNil(t, err)
	assert.Equal(t, 500, err.Code)
	assert.Equal(t, "Internal Server Error", err.Message.Message)
}
