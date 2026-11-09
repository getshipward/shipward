package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"go.yaml.in/yaml/v3"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/sbom"
)

const licencesHeader = `# Licences a person checked, one entry per component. cra sbom writes them into the SBOM as the
# "concluded" licence (BSI TR-03183-2: distribution licence). An entry without "@version" applies to every version
# while the declared licence stays the same. Check each entry before you commit this file.
`

func runLicences(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("licences", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to cra.yaml")
	write := fs.Bool("write", false, "add an entry for each unconfirmed component with one declared licence, to check by hand")
	if err := parse(fs, args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "cra licences: %v\n", err)
		return 1
	}
	path := fs.Arg(0)
	if path == "" {
		path = cfg.Resolve(cfg.SBOM.Output)
	}
	bom, err := readBOM(path)
	if err != nil {
		fmt.Fprintf(stderr, "cra licences: %v\n", err)
		return 1
	}

	var proposals []sbom.LicenceConfirmation
	var manual []string
	seen := map[string]bool{}
	for _, c := range components(bom) {
		if sbom.HasConcluded(c) {
			continue
		}
		declared := sbom.DeclaredLicence(c)
		if declared == "" || countLicences(c) > 1 {
			manual = append(manual, fmt.Sprintf("%s (declared: %s)", label(c), orNone(declared)))
			continue
		}
		_, key := sbom.ComponentKeys(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		proposals = append(proposals, sbom.LicenceConfirmation{Component: key, Declared: declared, Concluded: declared})
	}
	sort.Slice(proposals, func(i, j int) bool { return proposals[i].Component < proposals[j].Component })
	sort.Strings(manual)

	file := cfg.Resolve(cfg.SBOM.Licences)
	if *write && len(proposals) > 0 {
		if err := appendLicences(file, proposals); err != nil {
			fmt.Fprintf(stderr, "cra licences: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "added %d entries to %s. Check each one, then run cra sbom again.\n", len(proposals), file)
	} else {
		for _, p := range proposals {
			fmt.Fprintf(stdout, "unconfirmed  %-60s declared: %s\n", p.Component, p.Declared)
		}
		if len(proposals) > 0 {
			fmt.Fprintf(stdout, "\n%d component(s) can be confirmed with cra licences --write (then check %s by hand).\n", len(proposals), file)
		}
	}
	if len(manual) > 0 {
		fmt.Fprintf(stdout, "\n%d component(s) need a person to find the licence and add it to %s:\n", len(manual), file)
		for _, m := range manual {
			fmt.Fprintf(stdout, "  %s\n", m)
		}
	}
	if len(proposals) == 0 && len(manual) == 0 {
		fmt.Fprintln(stdout, "Every component has a confirmed licence.")
	}
	return 0
}

// components returns the product and its components, without file listings.
func components(bom *cyclonedx.BOM) []cyclonedx.Component {
	var out []cyclonedx.Component
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.Type != cyclonedx.ComponentTypeFile {
				out = append(out, c)
			}
		}
	}
	return out
}

// countLicences counts declared licence entries; several separate ones may be a choice, not "all apply".
func countLicences(c cyclonedx.Component) int {
	if c.Licenses == nil {
		return 0
	}
	return len(*c.Licenses)
}

func label(c cyclonedx.Component) string {
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// appendLicences adds entries at the end of licences.yaml. The file is a YAML list, so appending keeps the person's
// comments and order.
func appendLicences(path string, entries []sbom.LicenceConfirmation) error {
	data, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var out []byte
	if len(old) == 0 {
		out = append([]byte(licencesHeader), data...)
	} else {
		out = old
		if old[len(old)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, data...)
	}
	return writeFile(path, func(w io.Writer) error {
		_, err := w.Write(out)
		return err
	})
}
