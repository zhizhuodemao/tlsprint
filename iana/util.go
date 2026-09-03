package iana

import (
	"strconv"
	"strings"
)

// parseNumericID parses a numeric identifier: decimal by default, hex when
// prefixed with "0x".
func parseNumericID(s string) (uint16, bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	if strings.HasPrefix(t, "0x") {
		n, err := strconv.ParseUint(t[2:], 16, 16)
		if err != nil {
			return 0, false
		}
		return uint16(n), true
	}
	n, err := strconv.ParseUint(t, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}
