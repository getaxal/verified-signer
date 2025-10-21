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
		return "user"
	case AxalInitiatedSigning:
		return "axal"
	default:
		return "unknown"
	}
}
