package data

import (
	"fmt"
	"regexp"
	"strings"
)

// Privy caps external ids at 64 characters and accepts only [a-zA-Z0-9_-].
const maxExternalIDLength = 64

var (
	// Stricter than purposePattern on purpose: a wallet purpose becomes part of a Privy
	// external id, whose charset excludes the dots purposePattern allows.
	walletPurposePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

	// The subject of a Privy DID. Checked rather than assumed, since it is concatenated
	// into an identifier with a restricted charset.
	privySubjectPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// CreateUserWalletRequest asks for an additional delegated eth wallet for the
// authenticated user, identified by what the wallet is for.
//
// The HD index is deliberately not part of this API. Privy's server API will not let us
// pin one — wallet_index is read-only on the wallet it returns — so an index in the
// request would promise something we cannot honour. A purpose is something we can honour:
// it maps to a stable external id, which is how the wallet is recognised on a repeat call.
type CreateUserWalletRequest struct {
	Purpose string `json:"purpose"`
}

func (req *CreateUserWalletRequest) Validate() error {
	if !walletPurposePattern.MatchString(req.Purpose) {
		return fmt.Errorf("purpose must be a lowercase identifier of up to 32 characters")
	}
	return nil
}

// Derives the Privy external id for one of a user's purpose-built wallets.
//
// The did:privy: prefix is dropped because ':' is outside the charset Privy accepts. What
// remains is stable per user and per purpose, which is what makes provisioning repeatable:
// asking twice names the same wallet both times.
func WalletExternalID(privyId string, purpose string) (string, error) {
	if !walletPurposePattern.MatchString(purpose) {
		return "", fmt.Errorf("purpose must be a lowercase identifier of up to 32 characters")
	}

	subject := privyId[strings.LastIndex(privyId, ":")+1:]
	if !privySubjectPattern.MatchString(subject) {
		return "", fmt.Errorf("privy id does not have a usable subject")
	}

	externalID := subject + "-" + purpose
	if len(externalID) > maxExternalIDLength {
		return "", fmt.Errorf("external id for purpose %q exceeds %d characters", purpose, maxExternalIDLength)
	}

	return externalID, nil
}

// Reports whether an external id is one this enclave would have assigned to the given user.
//
// This is an ownership check, not a formatting check. A wallet created on Privy's wallet API
// is owned by a key quorum and does not appear among the user's linked accounts, so the
// record that usually proves "this wallet is theirs" is not available for one. The external
// id stands in for it: the enclave is what assigns it, it is derived from the user's own DID
// subject, and Privy holds external ids unique per app and write-once — so a wallet carrying
// this user's id was provisioned for this user and cannot have been taken over by another.
//
// The purpose is round-tripped through WalletExternalID rather than compared by prefix, so
// there is one definition of the mapping and no way for a crafted id to satisfy a looser
// version of it.
func ExternalIDBelongsToUser(externalID string, privyId string) bool {
	if externalID == "" {
		return false
	}

	subject := privyId[strings.LastIndex(privyId, ":")+1:]
	if !strings.HasPrefix(externalID, subject+"-") {
		return false
	}

	expected, err := WalletExternalID(privyId, strings.TrimPrefix(externalID, subject+"-"))

	return err == nil && expected == externalID
}
