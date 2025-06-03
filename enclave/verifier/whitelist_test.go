package verifier

import "testing"

func TestInitWhitelist(t *testing.T) {
	// Test initialization
	InitWhitelist()

	if verifiedAddresses == nil {
		t.Fatal("InitWhitelist() should initialize verifiedAddresses")
	}

	if verifiedAddresses.addressList == nil {
		t.Fatal("InitWhitelist() should initialize addressList map")
	}

	if len(verifiedAddresses.addressList) != 0 {
		t.Errorf("Expected empty whitelist after init, got %d items", len(verifiedAddresses.addressList))
	}
}

func TestAddToWhiteList(t *testing.T) {
	// Setup
	InitWhitelist()

	testCases := []struct {
		name    string
		address string
	}{
		{
			name:    "Add valid address",
			address: "0x742d35Cc6634C0532925a3b8D93b9f2d4d22aA4e",
		},
		{
			name:    "Add another address",
			address: "0x1234567890123456789012345678901234567890",
		},
		{
			name:    "Add empty string",
			address: "",
		},
		{
			name:    "Add duplicate address",
			address: "0x742d35Cc6634C0532925a3b8D93b9f2d4d22aA4e", // Duplicate
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifiedAddresses.AddToWhiteList(tc.address)

			if !verifiedAddresses.IsWhitelisted(tc.address) {
				t.Errorf("Address %s should be whitelisted after adding", tc.address)
			}

			// Verify it's set to true in the map
			if val, exists := verifiedAddresses.addressList[tc.address]; !exists || !val {
				t.Errorf("Address %s should exist in map with value true", tc.address)
			}
		})
	}
}

func TestRemoveFromWhiteList(t *testing.T) {
	// Setup
	InitWhitelist()
	address := "0x742d35Cc6634C0532925a3b8D93b9f2d4d22aA4e"

	// Add address first
	verifiedAddresses.AddToWhiteList(address)

	// Verify it's added
	if !verifiedAddresses.IsWhitelisted(address) {
		t.Fatal("Address should be whitelisted before removal test")
	}

	// Remove address
	verifiedAddresses.RemoveFromWhiteList(address)

	// Verify it's removed (should return false)
	if verifiedAddresses.IsWhitelisted(address) {
		t.Errorf("Address %s should not be whitelisted after removal", address)
	}

	// Verify the map entry is set to false (not deleted)
	if val, exists := verifiedAddresses.addressList[address]; !exists || val {
		t.Errorf("Address %s should exist in map with value false after removal", address)
	}
}

func TestRemoveNonExistentAddress(t *testing.T) {
	// Setup
	InitWhitelist()
	address := "0xnonexistent"

	// Remove address that was never added
	verifiedAddresses.RemoveFromWhiteList(address)

	// Should be false
	if verifiedAddresses.IsWhitelisted(address) {
		t.Errorf("Non-existent address should not be whitelisted")
	}

	// Should exist in map with false value
	if val, exists := verifiedAddresses.addressList[address]; !exists || val {
		t.Errorf("Removed address should exist in map with value false")
	}
}

func TestIsWhitelisted(t *testing.T) {
	// Setup
	InitWhitelist()

	testCases := []struct {
		name     string
		address  string
		add      bool
		expected bool
	}{
		{
			name:     "Check non-existent address",
			address:  "0x1111111111111111111111111111111111111111",
			add:      false,
			expected: false,
		},
		{
			name:     "Check added address",
			address:  "0x2222222222222222222222222222222222222222",
			add:      true,
			expected: true,
		},
		{
			name:     "Check empty string",
			address:  "",
			add:      false,
			expected: false,
		},
		{
			name:     "Check added empty string",
			address:  "",
			add:      true,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset whitelist for each test
			InitWhitelist()

			if tc.add {
				verifiedAddresses.AddToWhiteList(tc.address)
			}

			result := verifiedAddresses.IsWhitelisted(tc.address)
			if result != tc.expected {
				t.Errorf("IsWhitelisted(%s) = %v, expected %v", tc.address, result, tc.expected)
			}
		})
	}
}

func TestWhiteListWorkflow(t *testing.T) {
	// Test complete workflow
	InitWhitelist()

	addresses := []string{
		"0x742d35Cc6634C0532925a3b8D93b9f2d4d22aA4e",
		"0x1234567890123456789012345678901234567890",
		"0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
	}

	// Add all addresses
	for _, addr := range addresses {
		verifiedAddresses.AddToWhiteList(addr)
	}

	// Verify all are whitelisted
	for _, addr := range addresses {
		if !verifiedAddresses.IsWhitelisted(addr) {
			t.Errorf("Address %s should be whitelisted", addr)
		}
	}

	// Remove middle address
	verifiedAddresses.RemoveFromWhiteList(addresses[1])

	// Verify first and third are still whitelisted
	if !verifiedAddresses.IsWhitelisted(addresses[0]) {
		t.Errorf("Address %s should still be whitelisted", addresses[0])
	}
	if !verifiedAddresses.IsWhitelisted(addresses[2]) {
		t.Errorf("Address %s should still be whitelisted", addresses[2])
	}

	// Verify middle is not whitelisted
	if verifiedAddresses.IsWhitelisted(addresses[1]) {
		t.Errorf("Address %s should not be whitelisted after removal", addresses[1])
	}

	// Re-add the removed address
	verifiedAddresses.AddToWhiteList(addresses[1])

	// Verify it's whitelisted again
	if !verifiedAddresses.IsWhitelisted(addresses[1]) {
		t.Errorf("Address %s should be whitelisted after re-adding", addresses[1])
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Basic test for potential race conditions
	InitWhitelist()

	address := "0x742d35Cc6634C0532925a3b8D93b9f2d4d22aA4e"

	// This is a simple test - for real concurrent testing you'd use goroutines
	// and sync primitives, but that would require modifying your struct
	for i := 0; i < 100; i++ {
		verifiedAddresses.AddToWhiteList(address)
		if !verifiedAddresses.IsWhitelisted(address) {
			t.Errorf("Address should be whitelisted on iteration %d", i)
		}
		verifiedAddresses.RemoveFromWhiteList(address)
		if verifiedAddresses.IsWhitelisted(address) {
			t.Errorf("Address should not be whitelisted after removal on iteration %d", i)
		}
	}
}

func TestNilWhiteList(t *testing.T) {
	// Test behavior when whitelist instance is nil
	var nilWhitelist *WhiteList

	address := "0x742d35Cc6634C0532925a3b8D93b9f2d4d22aA4e"

	// Test AddToWhiteList on nil instance - should panic
	t.Run("AddToWhiteList on nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when calling AddToWhiteList on nil whitelist")
			}
		}()
		nilWhitelist.AddToWhiteList(address)
	})

	// Test IsWhitelisted on nil instance - should panic
	t.Run("IsWhitelisted on nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when calling IsWhitelisted on nil whitelist")
			}
		}()
		nilWhitelist.IsWhitelisted(address)
	})

	// Test RemoveFromWhiteList on nil instance - should panic
	t.Run("RemoveFromWhiteList on nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when calling RemoveFromWhiteList on nil whitelist")
			}
		}()
		nilWhitelist.RemoveFromWhiteList(address)
	})

	// Test with properly initialized whitelist
	t.Run("Valid whitelist operations", func(t *testing.T) {
		wl := &WhiteList{addressList: make(map[string]bool)}

		wl.AddToWhiteList(address)
		if !wl.IsWhitelisted(address) {
			t.Errorf("Address should be whitelisted")
		}

		wl.RemoveFromWhiteList(address)
		if wl.IsWhitelisted(address) {
			t.Errorf("Address should not be whitelisted after removal")
		}
	})
}
