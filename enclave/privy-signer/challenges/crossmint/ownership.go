// Package crossmint validates provider-issued wallet ownership challenges
// before the enclave allows them to reach a signing primitive.
package crossmint

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const challengeHeader = "crossmint.com wants you to sign in with your blockchain account:"

// ValidateOwnership validates the Crossmint CAIP-122 message, its binding to
// the requested wallet, and the provider/chain/time constraints enforced by
// Axal. The exact validated message is subsequently signed with EIP-191
// personal_sign semantics.
func ValidateOwnership(message, walletAddress string, now time.Time) error {
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	if len(lines) < 8 || strings.TrimSpace(lines[0]) != challengeHeader {
		return fmt.Errorf("message is not a Crossmint CAIP-122 challenge")
	}

	challengeAddress := strings.TrimSpace(lines[1])
	if !strings.EqualFold(challengeAddress, walletAddress) {
		return fmt.Errorf("challenge wallet does not match requested wallet")
	}

	fields := make(map[string]string)
	for _, line := range lines[2:] {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, ":")
		if found {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	if fields["Version"] != "1" || fields["Nonce"] == "" || fields["Request ID"] == "" {
		return fmt.Errorf("challenge is missing required CAIP-122 fields")
	}
	uri, err := url.Parse(fields["URI"])
	if err != nil || uri.Scheme != "https" || !isCrossmintHost(uri.Hostname()) {
		return fmt.Errorf("challenge URI is not controlled by Crossmint")
	}
	if !isAllowedChain(fields["Chain ID"]) {
		return fmt.Errorf("challenge chain is not allowed")
	}

	issuedAt, err := time.Parse(time.RFC3339, fields["Issued At"])
	if err != nil || issuedAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("challenge issued-at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, fields["Expiration Time"])
	if err != nil || !expiresAt.After(now) || !expiresAt.After(issuedAt) {
		return fmt.Errorf("challenge expiration is invalid")
	}

	return nil
}

func isCrossmintHost(host string) bool {
	return host == "crossmint.com" || strings.HasSuffix(host, ".crossmint.com")
}

func isAllowedChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "base", "base-sepolia", "eip155:8453", "eip155:84532":
		return true
	default:
		return false
	}
}
