package security

import (
	"net/url"
	"strings"
)

func ValidReturnTo(value string) bool {
	if value == "" {
		return false
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return false
	}
	if strings.HasPrefix(value, `//`) || strings.HasPrefix(value, `/\`) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	if parsed.IsAbs() || parsed.Host != "" {
		return false
	}
	return strings.HasPrefix(parsed.Path, "/")
}
