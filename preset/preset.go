// Package preset ships a curated, versioned collection of fingerprints of
// real TLS clients (browsers and common tooling), loadable by name.
//
// A Preset wraps the engine-independent tlsprint.Profile with metadata
// (product, platform, browser version, upstream identifier). The built-in
// collection is embedded from JSON data files under preset/data and is
// strictly read-only — look it up, copy it, and modify the copy if you need a
// variant.
//
// Data provenance: the curated profiles are observational snapshots of real
// browser traffic (the same captures published by curl_cffi / curl-impersonate
// style fingerprint configs). They are facts about wire behaviour, included
// here with their source identifiers; see preset/data/README.md for the full
// provenance and how to regenerate the collection.
package preset

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lingulingo/tlsprint"
)

// Preset is one named client fingerprint.
type Preset struct {
	// Key is the stable lookup key of this preset, e.g.
	// "TLS_CHROME_142_MACOS_10_15_7" (matching the source identifier) — or
	// a canonical name for hand-authored presets.
	Key string `json:"key"`

	// ID is the upstream capture/source identifier when known (e.g. the
	// snapshot UUID in the reference collection).
	ID string `json:"id,omitempty"`

	// Product is the client product, e.g. "chrome", "firefox", "curl".
	Product string `json:"product,omitempty"`

	// Platform is the client platform when known, e.g. "windows", "macos",
	// "android", "ios".
	Platform string `json:"platform,omitempty"`

	// Version is the client version string when known, e.g. "142" or
	// "8.15.0".
	Version string `json:"version,omitempty"`

	// Description is an optional human readable note.
	Description string `json:"description,omitempty"`

	// Profile holds the actual fingerprint data. Embedded anonymously so the
	// JSON encoding is flat: {"key":..., "tls":{...}, "http2":{...}}.
	tlsprint.Profile
}

// Name returns Key unchanged (kept for readability at call sites that treat
// presets like enums).
func (p *Preset) Name() string {
	if p == nil {
		return ""
	}
	return p.Key
}

// UserAgent returns the preset's default User-Agent, if declared.
func (p *Preset) UserAgent() string {
	if p == nil || p.Profile.Headers == nil {
		return ""
	}
	return p.Profile.Headers.UserAgent()
}

// Registry is an immutable, indexed view over a set of presets.
type Registry struct {
	presets []*Preset

	byKey   map[string]*Preset
	byName  map[string]*Preset
	byAlias map[string]*Preset
}

// NewRegistry indexes the given presets (a defensive copy is taken). The
// product name ("chrome", "curl", ...) resolves to the newest preset of that
// product according to the registry's sort order.
func NewRegistry(presets []*Preset) (*Registry, error) {
	r := &Registry{
		presets: make([]*Preset, len(presets)),
		byKey:   make(map[string]*Preset, len(presets)),
		byName:  make(map[string]*Preset, len(presets)),
		byAlias: make(map[string]*Preset, len(presets)),
	}
	copy(r.presets, presets)
	for _, p := range presets {
		if p == nil {
			continue
		}
		if _, dup := r.byKey[normalize(p.Key)]; dup {
			return nil, fmt.Errorf("preset: duplicate key %q", p.Key)
		}
		r.byKey[normalize(p.Key)] = p
	}
	sort.Slice(r.presets, func(i, j int) bool {
		a, b := r.presets[i], r.presets[j]
		if a.Product != b.Product {
			return a.Product < b.Product
		}
		if c := compareVersion(a.Version, b.Version); c != 0 {
			return c < 0
		}
		return a.Key < b.Key
	})
	// Latest per product: sorted ascending, so the last one of each product
	// wins. A product-version alias ("chrome-152") is also registered so both
	// `Lookup("chrome")` and `Lookup("chrome-152")` work.
	for _, p := range r.presets {
		if p.Product != "" {
			r.byName[normalize(p.Product)] = p
		}
		if p.Product != "" && p.Version != "" {
			r.byAlias[normalize(p.Product+"-"+p.Version)] = p
		}
	}
	return r, nil
}

// AddAlias registers an additional lookup name for a preset already in the
// registry (e.g. product-level names such as "chrome" → the newest chrome).
func (r *Registry) AddAlias(alias string, target string) error {
	t, ok := r.byKey[normalize(target)]
	if !ok {
		return fmt.Errorf("preset: unknown target %q for alias %q", target, alias)
	}
	r.byAlias[normalize(alias)] = t
	return nil
}

// Lookup resolves a preset by any of its names: exact key, normalized key
// (lower-case, '_' as '-', optional "tls-" prefix), a product-version alias
// ("chrome-152"), an alias registered via AddAlias, or a product name
// ("chrome"). Returns nil when nothing matches.
func (r *Registry) Lookup(name string) *Preset {
	n := normalize(name)
	if p, ok := r.byKey[n]; ok {
		return p
	}
	if !strings.HasPrefix(n, "tls-") {
		if p, ok := r.byKey["tls-"+n]; ok {
			return p
		}
	}
	if p, ok := r.byName[n]; ok {
		return p
	}
	if p, ok := r.byAlias[n]; ok {
		return p
	}
	return nil
}

// List returns all presets sorted by product/version/key.
func (r *Registry) List() []*Preset {
	out := make([]*Preset, len(r.presets))
	copy(out, r.presets)
	return out
}

// Products returns the distinct product names present in the registry.
func (r *Registry) Products() []string {
	set := make(map[string]bool)
	for _, p := range r.presets {
		if p.Product != "" {
			set[p.Product] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normalize(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", "-"))
}

// compareVersion compares two version strings numerically, segment by
// segment ("8.4.0" < "8.16.0", "149.0.7827.197" < "152"). Segments are split
// on '.' and '-'; non-numeric segments compare as 0, and missing segments
// compare as 0, so "152" == "152.0" but "152" > "149.0.7827.197".
func compareVersion(a, b string) int {
	as, bs := splitVersion(a), splitVersion(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = versionSeg(as[i])
		}
		if i < len(bs) {
			bv = versionSeg(bs[i])
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
}

func versionSeg(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// ---- built-in registry ----

//go:embed data/registry.json
var builtinJSON []byte

var (
	builtinOnce sync.Once
	builtinReg  *Registry
	builtinErr  error
)

// Builtin returns the registry of curated presets embedded in the package.
func Builtin() (*Registry, error) {
	builtinOnce.Do(func() {
		var data struct {
			Presets []*Preset `json:"presets"`
		}
		if err := json.Unmarshal(builtinJSON, &data); err != nil {
			builtinErr = fmt.Errorf("preset: decode builtin data: %w", err)
			return
		}
		builtinReg, builtinErr = NewRegistry(data.Presets)
	})
	return builtinReg, builtinErr
}

// MustBuiltin is Builtin but panics on error; convenient for tests and
// tooling against a collection that is compiled into the binary.
func MustBuiltin() *Registry {
	r, err := Builtin()
	if err != nil {
		panic(err)
	}
	return r
}
