package data

// SigningType represents who is doing the signing
type SigningType int

const (
	UserInitiatedSigning SigningType = iota
	AxalInitiatedSigning
)

// String method for SigningType
func (s SigningType) String() string {
	switch s {
	case UserInitiatedSigning:
		return "User"
	case AxalInitiatedSigning:
		return "Axal"
	default:
		return "Unknown"
	}
}
