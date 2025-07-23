package data

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// BigInt wraps big.Int with proper JSON marshaling/unmarshaling
// @Description Large integer that preserves precision by using string representation in JSON
// @Example "123456789012345678901234567890"
type BigInt struct {
	*big.Int `format:"bigint" example:"100000000"`
}

// NewBigInt creates a new BigInt from various sources
func NewBigInt(value interface{}) (*BigInt, error) {
	b := &BigInt{big.NewInt(0)}

	switch v := value.(type) {
	case int64:
		b.Int.SetInt64(v)
	case string:
		if _, ok := b.Int.SetString(v, 10); !ok {
			return nil, fmt.Errorf("invalid big integer string: %s", v)
		}
	case *big.Int:
		if v != nil {
			b.Int.Set(v)
		}
	case big.Int:
		b.Int.Set(&v)
	case nil:
		// Keep as zero
	default:
		return nil, fmt.Errorf("unsupported type for BigInt: %T", value)
	}

	return b, nil
}

// NewBigIntFromString creates a BigInt from a string
func NewBigIntFromString(s string) (*BigInt, error) {
	return NewBigInt(s)
}

// NewBigIntFromInt64 creates a BigInt from an int64
func NewBigIntFromInt64(i int64) *BigInt {
	return &BigInt{big.NewInt(i)}
}

// MarshalJSON implements json.Marshaler
func (b *BigInt) MarshalJSON() ([]byte, error) {
	if b == nil || b.Int == nil {
		return []byte("null"), nil
	}
	// Marshal as JSON string to preserve precision
	return json.Marshal(b.Int.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (b *BigInt) UnmarshalJSON(data []byte) error {
	// Handle null case
	if string(data) == "null" {
		b.Int = big.NewInt(0)
		return nil
	}

	// Initialize if needed
	if b.Int == nil {
		b.Int = big.NewInt(0)
	}

	// Try to unmarshal as string first (preferred format)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if _, ok := b.Int.SetString(s, 10); !ok {
			return fmt.Errorf("invalid big integer string: %s", s)
		}
		return nil
	}

	// Try to unmarshal as number (for compatibility)
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		if _, ok := b.Int.SetString(string(n), 10); !ok {
			return fmt.Errorf("invalid big integer number: %s", n)
		}
		return nil
	}

	// If both fail, try raw string without quotes
	s = strings.Trim(string(data), `"`)
	if _, ok := b.Int.SetString(s, 10); !ok {
		return fmt.Errorf("invalid big integer value: %s", data)
	}

	return nil
}

// String returns the string representation
func (b *BigInt) String() string {
	if b == nil || b.Int == nil {
		return "0"
	}
	return b.Int.String()
}

// IsZero checks if the BigInt is zero
func (b *BigInt) IsZero() bool {
	return b == nil || b.Int == nil || b.Int.Sign() == 0
}

// IsNil checks if the BigInt is nil
func (b *BigInt) IsNil() bool {
	return b == nil || b.Int == nil
}

// Copy creates a deep copy of the BigInt
func (b *BigInt) Copy() *BigInt {
	if b == nil || b.Int == nil {
		return &BigInt{big.NewInt(0)}
	}
	return &BigInt{new(big.Int).Set(b.Int)}
}

// Add adds two BigInts and returns a new BigInt
func (b *BigInt) Add(other *BigInt) *BigInt {
	if b == nil || b.Int == nil {
		if other == nil || other.Int == nil {
			return &BigInt{big.NewInt(0)}
		}
		return other.Copy()
	}
	if other == nil || other.Int == nil {
		return b.Copy()
	}

	result := new(big.Int).Add(b.Int, other.Int)
	return &BigInt{result}
}

// Sub subtracts other from b and returns a new BigInt
func (b *BigInt) Sub(other *BigInt) *BigInt {
	if b == nil || b.Int == nil {
		if other == nil || other.Int == nil {
			return &BigInt{big.NewInt(0)}
		}
		return &BigInt{new(big.Int).Neg(other.Int)}
	}
	if other == nil || other.Int == nil {
		return b.Copy()
	}

	result := new(big.Int).Sub(b.Int, other.Int)
	return &BigInt{result}
}

// Mul multiplies two BigInts and returns a new BigInt
func (b *BigInt) Mul(other *BigInt) *BigInt {
	if b == nil || b.Int == nil || other == nil || other.Int == nil {
		return &BigInt{big.NewInt(0)}
	}

	result := new(big.Int).Mul(b.Int, other.Int)
	return &BigInt{result}
}

// Cmp compares two BigInts (-1 if b < other, 0 if equal, 1 if b > other)
func (b *BigInt) Cmp(other *BigInt) int {
	if b == nil || b.Int == nil {
		if other == nil || other.Int == nil {
			return 0
		}
		return -other.Int.Sign()
	}
	if other == nil || other.Int == nil {
		return b.Int.Sign()
	}
	return b.Int.Cmp(other.Int)
}

// Equals checks if two BigInts are equal
func (b *BigInt) Equals(other *BigInt) bool {
	return b.Cmp(other) == 0
}

// Int64 returns the int64 representation if possible
func (b *BigInt) Int64() (int64, bool) {
	if b == nil || b.Int == nil {
		return 0, true
	}
	if !b.Int.IsInt64() {
		return 0, false
	}
	return b.Int.Int64(), true
}

// Uint64 returns the uint64 representation if possible
func (b *BigInt) Uint64() (uint64, bool) {
	if b == nil || b.Int == nil {
		return 0, true
	}
	if !b.Int.IsUint64() {
		return 0, false
	}
	return b.Int.Uint64(), true
}
