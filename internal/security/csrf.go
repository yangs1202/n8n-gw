package security

import (
	"crypto/subtle"
)

func NewCSRFToken() (string, error) {
	return RandomBase64URL(32)
}

func EqualToken(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
