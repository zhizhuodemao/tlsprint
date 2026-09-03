// Command tlsprint is a small CLI for the tlsprint fingerprint library:
// listing and inspecting curated client fingerprints and computing JA3/JA4
// fingerprints from profiles or captured ClientHello bytes.
//
// Examples:
//
//	tlsprint list                # list all curated presets
//	tlsprint list chrome         # only chrome presets
//	tlsprint show chrome-141     # JSON profile of a preset
//	tlsprint fp -preset chrome   # JA3/JA3-md5 of the newest chrome preset
//	tlsprint fp -hex 160303...   # JA3/JA4 of a captured ClientHello (hex)
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/ja3"
	"github.com/lingulingo/tlsprint/ja4"
	"github.com/lingulingo/tlsprint/preset"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		err = cmdList(os.Args[2:])
	case "show":
		err = cmdShow(os.Args[2:])
	case "fp":
		err = cmdFP(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "tlsprint: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tlsprint:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tlsprint — TLS fingerprint toolkit

Usage:
  tlsprint list [product]        list curated presets (optionally one product)
  tlsprint show <preset>         print a preset as JSON
  tlsprint fp -preset <preset>   print the canonical JA3 (+md5) of a preset
  tlsprint fp -hex <hex>         print JA3/JA4 of captured ClientHello bytes
                                 (full TLS record, bare handshake, or body)

Presets can be named like "TLS_CHROME_141" or "chrome" (newest of a product).
`)
}

func cmdList(args []string) error {
	reg := preset.MustBuiltin()
	filter := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		filter = args[0]
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tPRODUCT\tPLATFORM\tVERSION\tCIPHERS\tEXT\tUSER-AGENT")
	for _, p := range reg.List() {
		if filter != "" && p.Product != filter {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			p.Key, orDash(p.Product), orDash(p.Platform), orDash(p.Version),
			len(p.TLS.CipherSuites), len(p.TLS.Extensions), shortUA(p))
	}
	return w.Flush()
}

func cmdShow(args []string) error {
	name := firstArg(args)
	if name == "" {
		return fmt.Errorf("show requires a preset name")
	}
	p := lookup(name)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

func cmdFP(args []string) error {
	fs := flag.NewFlagSet("fp", flag.ExitOnError)
	presetName := fs.String("preset", "", "preset name")
	hexData := fs.String("hex", "", "hex-encoded ClientHello bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case *presetName != "":
		p := lookup(*presetName)
		ja3s := ja3.FromProfile(&p.TLS)
		fmt.Printf("preset   %s (%s %s)\n", p.Key, orDash(p.Product), orDash(p.Version))
		fmt.Printf("ja3      %s\n", ja3s)
		fmt.Printf("ja3_md5  %s\n", ja3.Hash(ja3s))
		fmt.Println("note     JA4 depends on SNI/ALPN payloads of a live handshake;")
		fmt.Println("         compute it from captured bytes with: tlsprint fp -hex ...")
	case *hexData != "":
		raw, err := parseHex(*hexData)
		if err != nil {
			return fmt.Errorf("bad hex: %w", err)
		}
		ch, err := hello.Parse(raw)
		if err != nil {
			return fmt.Errorf("parse client hello: %w", err)
		}
		ja3s := ja3.Compute(ch)
		fmt.Printf("ja3      %s\n", ja3s)
		fmt.Printf("ja3_md5  %s\n", ja3.Hash(ja3s))
		j4, err := ja4.Compute(ch)
		if err != nil {
			return err
		}
		fmt.Printf("ja4      %s\n", j4)
	default:
		return fmt.Errorf("fp requires -preset or -hex")
	}
	return nil
}

func lookup(name string) *preset.Preset {
	reg := preset.MustBuiltin()
	p := reg.Lookup(name)
	if p == nil {
		fmt.Fprintf(os.Stderr, "tlsprint: unknown preset %q\n", name)
		os.Exit(1)
	}
	return p
}

func firstArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func shortUA(p *preset.Preset) string {
	ua := strings.TrimSpace(p.UserAgent())
	if i := strings.Index(ua, "Mozilla"); i >= 0 {
		ua = ua[i:]
	}
	if len(ua) > 56 {
		ua = ua[:53] + "..."
	}
	return orDash(ua)
}

func parseHex(s string) ([]byte, error) {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			sb.WriteRune(r)
		}
	}
	return hex.DecodeString(sb.String())
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
