// Command importproteus converts a dump of the reference "proteus" preset
// collection (curl_cffi-style tls_config fingerprints) into the canonical
// tlsprint preset data file (preset/data/registry.json).
//
// The reference projects are not imported as Go modules here; this tool only
// consumes a JSON dump of their preset variables, produced once by exporting
// the local checkout (see preset/data/README.md "Regenerating"). This keeps
// the tlsprint module dependency-free.
//
// Usage:
//
//	go run ./tools/importproteus \
//	   -in /path/to/proteus_dump.json \
//	   -allow preset/data/ALLOWLIST.txt \
//	   -out preset/data/registry.json
//
// The dump schema is the JSON encoding of the reference Config struct with a
// "__name" key holding the TLS_* variable name:
//
//	[{"__name":"TLS_CHROME_141","JA3":"...","CipherSuites":"...",
//	  "ExtensionOrder":"...","Curves":"...","SigAlgs":"...",
//	  "H2Settings":{...},"H2SettingsOrder":[...], ...}, ...]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/iana"
	"github.com/lingulingo/tlsprint/preset"
)

// ---- reference Config shape (JSON field names == Go field names) ----

type srcConfig struct {
	ID                      string             `json:"ID"`
	JA3                     string             `json:"JA3"`
	RandomJA3               bool               `json:"RandomJA3"`
	ExtensionOrder          string             `json:"ExtensionOrder"`
	DisableGrease           bool               `json:"DisableGrease"`
	ClientHelloHexStream    string             `json:"ClientHelloHexStream"`
	TLS13Ciphers            string             `json:"TLS13Ciphers"`
	CipherSuites            string             `json:"CipherSuites"`
	SigAlgs                 string             `json:"SigAlgs"`
	SignatureAlgorithmsCert string             `json:"SignatureAlgorithmsCert"`
	Curves                  string             `json:"Curves"`
	CertCompression         string             `json:"CertCompression"`
	RecordSizeLimit         int                `json:"RecordSizeLimit"`
	DelegatedCredentials    string             `json:"DelegatedCredentials"`
	SupportedVersions       string             `json:"SupportedVersions"`
	PSKKeyExchangeModes     string             `json:"PSKKeyExchangeModes"`
	HTTPVersion             string             `json:"HTTPVersion"`
	SSLVersion              string             `json:"SSLVersion"`
	H2Settings              map[string]uint32  `json:"H2Settings"`
	H2SettingsOrder         []string           `json:"H2SettingsOrder"`
	H2SettingsAck           bool               `json:"H2SettingsAck"`
	H2ConnectionFlow        uint32             `json:"H2ConnectionFlow"`
	H2WindowUpdate          uint32             `json:"H2WindowUpdate"`
	H2HeadersID             uint32             `json:"H2HeadersID"`
	H2PseudoHeadersOrder    string             `json:"H2PseudoHeadersOrder"`
	H2HeaderPriority        *srcPriority       `json:"H2HeaderPriority"`
	H2PriorityFrames        []srcPriorityFrame `json:"H2PriorityFrames"`
	Headers                 map[string]string  `json:"Headers"`
	HeaderOrder             []string           `json:"HeaderOrder"`
	Name                    string             `json:"__name"`
}

type srcPriority struct {
	StreamDep uint32 `json:"StreamDep"`
	Exclusive bool   `json:"Exclusive"`
	Weight    uint8  `json:"Weight"`
}

type srcPriorityFrame struct {
	StreamID uint32      `json:"StreamID"`
	Priority srcPriority `json:"Priority"`
}

// ---- allowlist selection ----

type selection struct {
	Product  string // override product classification when set
	Platform string // override platform when set
	Version  string // override version when set
}

func main() {
	var (
		inFile    = flag.String("in", "", "path to the proteus config dump JSON")
		allowFile = flag.String("allow", "", "path to the ALLOWLIST file (one TLS_* name per line, # = comment)")
		outFile   = flag.String("out", "", "output registry.json path")
		verbose   = flag.Bool("v", false, "verbose per-preset report")
	)
	flag.Parse()
	if *inFile == "" || *allowFile == "" || *outFile == "" {
		flag.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("read dump: %v", err)
	}
	var cfgs []srcConfig
	if err := json.Unmarshal(raw, &cfgs); err != nil {
		log.Fatalf("decode dump: %v", err)
	}
	byName := make(map[string]srcConfig, len(cfgs))
	for _, c := range cfgs {
		if c.Name == "" {
			log.Fatalf("dump entry without __name")
		}
		byName[c.Name] = c
	}

	overrides, err := readAllowlist(*allowFile)
	if err != nil {
		log.Fatalf("allowlist: %v", err)
	}

	names := make([]string, 0, len(overrides))
	for n := range overrides {
		if _, ok := byName[n]; !ok {
			log.Fatalf("allowlist name %q not present in dump", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)

	var out struct {
		Source  string           `json:"source"`
		Presets []*preset.Preset `json:"presets"`
	}
	out.Source = "proteus preset collection (curl_cffi tls_config lineage), exported and curated for tlsprint"
	for _, n := range names {
		cfg := byName[n]
		p, err := convert(n, cfg)
		if err != nil {
			log.Fatalf("convert %s: %v", n, err)
		}
		if o, ok := overrides[n]; ok {
			if o.Product != "" {
				p.Product = o.Product
			}
			if o.Platform != "" {
				p.Platform = o.Platform
			}
			if o.Version != "" {
				p.Version = o.Version
			}
		}
		out.Presets = append(out.Presets, p)
		if *verbose {
			log.Printf("%-52s %-8s %-8s %-8s ja3=%s", p.Key, p.Product, p.Platform, p.Version, p.TLS.JA3)
		}
	}

	// Validate everything before writing.
	reg, err := preset.NewRegistry(out.Presets)
	if err != nil {
		log.Fatalf("registry: %v", err)
	}
	for _, p := range reg.List() {
		if err := p.Validate(); err != nil {
			log.Fatalf("preset %s invalid: %v", p.Key, err)
		}
	}

	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(*outFile, data, 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Printf("wrote %d presets to %s\n", len(out.Presets), *outFile)
}

// readAllowlist parses "NAME [product platform version]" lines; unset columns
// are left empty (auto-detected).
func readAllowlist(path string) (map[string]selection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]selection)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		sel := selection{}
		if len(fields) > 1 {
			sel.Product = strings.ToLower(fields[1])
		}
		if len(fields) > 2 {
			sel.Platform = strings.ToLower(fields[2])
		}
		if len(fields) > 3 {
			sel.Version = fields[3]
		}
		out[fields[0]] = sel
	}
	return out, sc.Err()
}

// convert maps one reference Config into the canonical preset representation.
func convert(name string, c srcConfig) (*preset.Preset, error) {
	p := &preset.Preset{
		Key:     name,
		ID:      c.ID,
		Profile: tlsprint.Profile{TLS: tlsprint.TLSProfile{}},
	}
	if c.RandomJA3 {
		p.TLS.RandomGrease = true
	}
	p.TLS.DisableGrease = c.DisableGrease
	p.TLS.JA3 = c.JA3

	// JA3 is the authoritative base for version/ciphers/extensions/groups/
	// ec-formats when present.
	var ja3Groups []uint16
	if c.JA3 != "" {
		parts := strings.Split(c.JA3, ",")
		if len(parts) == 5 {
			if v, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
				p.TLS.LegacyVersion = versionFromJA3(uint16(v))
			}
			p.TLS.CipherSuites = parseNumList(parts[1], "-", nil)
			// Extension order: prefer the dedicated field (may carry GREASE
			// markers), else the JA3 list.
			if c.ExtensionOrder != "" {
				p.TLS.Extensions = parseNumList(c.ExtensionOrder, "-", map[string]uint16{"GREASE": iana.GreaseMarker})
			} else {
				p.TLS.Extensions = parseNumList(parts[2], "-", nil)
			}
			ja3Groups = parseNumList(parts[3], "-", nil)
			if formats := parseNumList(parts[4], "-", nil); len(formats) > 0 {
				ec := make([]byte, len(formats))
				for i, f := range formats {
					ec[i] = byte(f)
				}
				p.TLS.ECFormats = ec
			}
		}
	}

	// Supported groups. The JA3 group list is the complete capture of what
	// was sent on the wire; the dedicated Curves field is usually the same
	// list but sometimes abbreviated ("GREASE:4588:X25519") and may record a
	// leading GREASE position. Prefer the full JA3 list and re-attach the
	// GREASE marker when the source declared one.
	switch {
	case len(ja3Groups) > 0:
		p.TLS.SupportedGroups = ja3Groups
		if strings.Contains(strings.ToUpper(c.Curves), "GREASE") {
			p.TLS.SupportedGroups = append([]uint16{iana.GreaseMarker}, p.TLS.SupportedGroups...)
		}
	case c.Curves != "":
		p.TLS.SupportedGroups = parseGroups(c.Curves)
	}

	if c.SigAlgs != "" {
		p.TLS.SignatureAlgorithms = parseSigAlgs(c.SigAlgs)
	}
	if c.SignatureAlgorithmsCert != "" {
		p.TLS.SignatureAlgorithmsCert = parseSigAlgs(c.SignatureAlgorithmsCert)
	}
	if c.DelegatedCredentials != "" {
		p.TLS.DelegatedCredentials = parseSigAlgs(c.DelegatedCredentials)
	}
	if c.SupportedVersions != "" {
		p.TLS.SupportedVersions = parseVersions(c.SupportedVersions)
	}
	if c.PSKKeyExchangeModes != "" {
		p.TLS.PSKKeyExchangeModes = parsePSKModes(c.PSKKeyExchangeModes)
	}
	if c.CertCompression != "" {
		p.TLS.CertCompression = parseCertCompression(c.CertCompression)
	}
	if c.RecordSizeLimit > 0 {
		p.TLS.RecordSizeLimit = uint16(c.RecordSizeLimit)
	}

	// HTTP/2 fingerprint.
	h2, err := convertHTTP2(c)
	if err != nil {
		return nil, err
	}
	if h2 != nil {
		p.HTTP2 = h2
	}

	// Header fingerprint.
	if len(c.Headers) > 0 || len(c.HeaderOrder) > 0 {
		hp := &tlsprint.HeaderProfile{Values: c.Headers}
		hp.Order = append([]string(nil), c.HeaderOrder...)
		p.Headers = hp
	}

	// Metadata derived from the source variable name (product/platform/
	// version), kept overridable by the allowlist file.
	deriveMeta(p, name)
	return p, nil
}

func convertHTTP2(c srcConfig) (*tlsprint.HTTP2Profile, error) {
	hasAny := len(c.H2Settings) > 0 || len(c.H2SettingsOrder) > 0 ||
		c.H2ConnectionFlow != 0 || c.H2WindowUpdate != 0 ||
		c.H2PseudoHeadersOrder != "" || c.H2HeaderPriority != nil ||
		len(c.H2PriorityFrames) > 0 || c.H2HeadersID != 0 || c.H2SettingsAck
	if !hasAny {
		return nil, nil
	}
	h2 := &tlsprint.HTTP2Profile{SettingsAck: c.H2SettingsAck}

	settings := make(map[uint16]uint32, len(c.H2Settings))
	for k, v := range c.H2Settings {
		id, err := strconv.ParseUint(k, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("h2 settings key %q: %w", k, err)
		}
		settings[uint16(id)] = v
	}
	// The settings order list is authoritative for wire order; only emit
	// parameters that carry a value.
	for _, name := range c.H2SettingsOrder {
		id, ok := iana.ParseHTTP2SettingName(name)
		if !ok {
			return nil, fmt.Errorf("unknown h2 settings name %q", name)
		}
		v, ok := settings[id]
		if !ok {
			continue
		}
		h2.Settings = append(h2.Settings, tlsprint.HTTP2Setting{ID: id, Value: v})
	}

	win := c.H2WindowUpdate
	if win == 0 {
		win = c.H2ConnectionFlow
	}
	h2.WindowUpdate = win
	h2.HeadersStreamID = c.H2HeadersID
	if c.H2PseudoHeadersOrder != "" {
		order, err := expandPseudoOrder(c.H2PseudoHeadersOrder)
		if err != nil {
			return nil, err
		}
		h2.PseudoHeaderOrder = order
	}
	if c.H2HeaderPriority != nil {
		h2.HeaderPriority = &tlsprint.H2Priority{
			StreamDep: c.H2HeaderPriority.StreamDep,
			Exclusive: c.H2HeaderPriority.Exclusive,
			Weight:    c.H2HeaderPriority.Weight,
		}
	}
	for _, f := range c.H2PriorityFrames {
		h2.PriorityFrames = append(h2.PriorityFrames, tlsprint.H2PriorityFrame{
			StreamID: f.StreamID,
			Priority: tlsprint.H2Priority{
				StreamDep: f.Priority.StreamDep,
				Exclusive: f.Priority.Exclusive,
				Weight:    f.Priority.Weight,
			},
		})
	}
	return h2, nil
}

// expandPseudoOrder converts the curl_cffi letter code ("masp") into the
// pseudo-header name list.
func expandPseudoOrder(code string) ([]string, error) {
	letters := map[byte]string{
		'm': ":method", 'a': ":authority", 's': ":scheme", 'p': ":path",
	}
	var out []string
	for i := 0; i < len(code); i++ {
		name, ok := letters[code[i]]
		if !ok {
			return nil, fmt.Errorf("unknown pseudo-header code %q in %q", string(code[i]), code)
		}
		out = append(out, name)
	}
	return out, nil
}

func versionFromJA3(v uint16) uint16 {
	if v == 0 {
		return 0x0303
	}
	return v
}

// parseNumList splits on sep and maps tokens through aliases ("GREASE").
func parseNumList(s, sep string, aliases map[string]uint16) []uint16 {
	var out []uint16
	for _, tok := range strings.Split(s, sep) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		up := strings.ToUpper(tok)
		if aliases != nil {
			if v, ok := aliases[up]; ok {
				out = append(out, v)
				continue
			}
		}
		if n, err := strconv.ParseUint(tok, 10, 16); err == nil {
			out = append(out, uint16(n))
		}
	}
	return out
}

// parseGroups handles colon- or dash-separated group lists that may contain
// GREASE tokens and named curves ("P-256").
func parseGroups(s string) []uint16 {
	sep := ":"
	if !strings.Contains(s, ":") {
		sep = "-"
	}
	var out []uint16
	for _, tok := range strings.Split(s, sep) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.EqualFold(tok, "GREASE") {
			out = append(out, iana.GreaseMarker)
			continue
		}
		if id, ok := iana.ParseGroupName(tok); ok {
			out = append(out, id)
			continue
		}
		if n, err := strconv.ParseUint(tok, 10, 16); err == nil {
			out = append(out, uint16(n))
		}
	}
	return out
}

func parseSigAlgs(s string) []uint16 {
	var out []uint16
	for _, tok := range strings.Split(s, ":") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if id, ok := iana.ParseSigAlgName(tok); ok {
			out = append(out, id)
		}
	}
	return out
}

func parseVersions(s string) []uint16 {
	var out []uint16
	for _, tok := range strings.Split(s, ":") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.EqualFold(tok, "GREASE") {
			out = append(out, iana.GreaseMarker)
			continue
		}
		if id, ok := iana.ParseVersionName(tok); ok {
			out = append(out, id)
		}
	}
	return out
}

func parsePSKModes(s string) []byte {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pskdhe":
		return []byte{1}
	case "pskke":
		return []byte{0}
	case "pskdhe:pskke", "pskke:pskdhe":
		return []byte{1, 0}
	default:
		var out []byte
		for _, tok := range strings.Split(strings.ToLower(s), ":") {
			switch strings.TrimSpace(tok) {
			case "pskdhe":
				out = append(out, 1)
			case "pskke":
				out = append(out, 0)
			}
		}
		return out
	}
}

func parseCertCompression(s string) []uint16 {
	ids := map[string]uint16{"zlib": 1, "brotli": 2, "zstd": 3}
	var out []uint16
	for _, tok := range strings.Split(strings.ToLower(s), ":") {
		tok = strings.TrimSpace(tok)
		if id, ok := ids[tok]; ok {
			out = append(out, id)
		}
	}
	return out
}

// deriveMeta fills Product/Platform/Version heuristics from a TLS_* name.
func deriveMeta(p *preset.Preset, name string) {
	toks := strings.Split(name, "_")
	if len(toks) < 2 || toks[0] != "TLS" {
		return
	}
	p.Product = strings.ToLower(toks[1])
	if p.Product == "android" && len(toks) > 2 && strings.ToUpper(toks[2]) == "OKHTTP" {
		p.Product = "okhttp" // TLS_ANDROID_OKHTTP_*
	}
	for _, t := range toks[2:] {
		switch strings.ToUpper(t) {
		case "WINDOWS", "WIN32", "WOW64":
			p.Platform = "windows"
		case "MACOS", "MAC", "OSX":
			p.Platform = "macos"
		case "ANDROID":
			p.Platform = "android"
		case "IOS", "IPHONE", "IPAD":
			p.Platform = "ios"
		case "LINUX":
			p.Platform = "linux"
		}
	}
	// Version: the first run of numeric tokens after the product token
	// ("8_15_0" → "8.15.0"). Non-numeric tokens before the run (e.g. IOS in
	// TLS_CHROME_IOS_17_4) are skipped.
	var nums []string
	for _, t := range toks[2:] {
		if isNumeric(t) {
			nums = append(nums, t)
		} else if len(nums) > 0 {
			break
		}
	}
	if len(nums) > 0 {
		p.Version = strings.Join(nums, ".")
	}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
