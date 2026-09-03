package iana

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// HTTP/2 SETTINGS parameter ids (RFC 7540 §6.5.2 and RFC 8441).
const (
	H2SettingsHeaderTableSize      = 0x1 // 1
	H2SettingsEnablePush           = 0x2 // 2
	H2SettingsMaxConcurrentStreams = 0x3 // 3
	H2SettingsInitialWindowSize    = 0x4 // 4
	H2SettingsMaxFrameSize         = 0x5 // 5
	H2SettingsMaxHeaderListSize    = 0x6 // 6
	// EnableConnectProtocol (0x8) is RFC 8441 (also known as 0x08).
	H2SettingsEnableConnectProtocol = 0x8
	// NoRFC7540Priorities (0x9) is RFC 9218.
	H2SettingsNoRFC7540Priorities = 0x9
)

// h2SettingNames maps SETTINGS ids to the curl_cffi-style uppercase names.
var h2SettingNames = map[uint16]string{
	H2SettingsHeaderTableSize:       "HEADER_TABLE_SIZE",
	H2SettingsEnablePush:            "ENABLE_PUSH",
	H2SettingsMaxConcurrentStreams:  "MAX_CONCURRENT_STREAMS",
	H2SettingsInitialWindowSize:     "INITIAL_WINDOW_SIZE",
	H2SettingsMaxFrameSize:          "MAX_FRAME_SIZE",
	H2SettingsMaxHeaderListSize:     "MAX_HEADER_LIST_SIZE",
	H2SettingsEnableConnectProtocol: "ENABLE_CONNECT_PROTOCOL",
	H2SettingsNoRFC7540Priorities:   "NO_RFC7540_PRIORITIES",
}

// HTTP2SettingName returns the uppercase name for a SETTINGS id, or "" when
// unknown. GREASE SETTINGS ids return "" (see IsGrease).
func HTTP2SettingName(id uint16) string {
	if IsGrease(id) {
		return ""
	}
	return h2SettingNames[id]
}

// HTTP2SettingDisplay renders a SETTINGS id as its name when known, else the
// curl_cffi-style UNKNOWN_SETTING_<decimal> form.
func HTTP2SettingDisplay(id uint16) string {
	if IsGrease(id) {
		return fmt.Sprintf("GREASE(0x%04x)", id)
	}
	if n := h2SettingNames[id]; n != "" {
		return n
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", id)
}

// ParseHTTP2SettingName parses a SETTINGS name (uppercase or the
// UNKNOWN_SETTING_<decimal> form) into its numeric id.
func ParseHTTP2SettingName(s string) (id uint16, ok bool) {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	if n, err := strconv.ParseUint(t, 10, 16); err == nil {
		return uint16(n), true
	}
	if strings.HasPrefix(t, "UNKNOWN_SETTING_") {
		if n, err := strconv.ParseUint(strings.TrimPrefix(t, "UNKNOWN_SETTING_"), 10, 16); err == nil {
			return uint16(n), true
		}
	}
	for id, name := range h2SettingNames {
		if name == t {
			return id, true
		}
	}
	return 0, false
}

// HTTP2SettingNames returns a sorted list of all known SETTINGS names.
func HTTP2SettingNames() []string {
	out := make([]string, 0, len(h2SettingNames))
	for _, n := range h2SettingNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
