// Command cra helps a small software maker prepare for the EU Cyber Resilience Act. See README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: cra <command> [flags]

commands:
  init        write cra.yaml and drafts of the CRA documents (SECURITY.md, security.txt, Annex II, V, VII)
  sbom        make a CycloneDX SBOM of the product (reads cra.yaml)
  check sbom  list fields the SBOM misses (BSI TR-03183-2 v2.1.0)
  scan        match the SBOM against public vulnerability data, on this machine
  triage      record decisions about advisories (VEX) and export them as OpenVEX
  report      reports of exploited vulnerabilities and severe incidents (CRA Art. 14): drafts and deadlines
  licences    list components without a confirmed licence (--write drafts licences.yaml)
  version     print the version
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "sbom":
		return runSBOM(ctx, args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "triage":
		return runTriage(ctx, args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "licences":
		return runLicences(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "cra: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// parse lets flags come after file names too (Go's flag package stops at the first argument that is not a flag), so
// "cra scan sbom.json --format json" works like "cra scan --format json sbom.json".
func parse(fs *flag.FlagSet, args []string) error {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		if f := fs.Lookup(name); f != nil {
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return fs.Parse(append(append(flags, "--"), pos...))
}
