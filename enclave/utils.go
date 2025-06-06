package enclave

import (
	"encoding/hex"
	"reflect"
)

func ToInt64Ptr(i int) *int64 {
	i64 := int64(i)
	return &i64
}

// Function that checks if a value is a pointer and dereferences it if it is.
func DereferenceIfPointer(v interface{}) interface{} {
	rv := reflect.ValueOf(v)

	// Check if it's a pointer
	if rv.Kind() == reflect.Ptr {
		// Check if it's not nil
		if !rv.IsNil() {
			return rv.Elem().Interface() // Dereference
		}
		return nil // It's a nil pointer
	}

	return v // Not a pointer, return as-is
}

// Function that marshalls bytes as json in hex format
func MarshalBytesToJSONHex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}
