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

const licencesHeader = `# Licences a person checked, one entry per component. shipward sbom writes them into the SBOM as the
# "concluded" licence (BSI TR-03183-2: distribution licence). An entry without "@version" applies to every version
# while the declared licence stays the same. Entries with "confirmed: false" are drafts from shipward licences --write:
# shipward sbom ignores them until you check the licence and remove that line (or set it to true).
`

// draftComment follows "confirmed: false" in every draft --write adds.
const draftComment = "check the licence, then remove this line"

func runLicences(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("licences", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	write := fs.Bool("write", false, "add a draft (confirmed: false) for each component with one declared SPDX licence, for a person to check")
	if err := parse(fs, args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward licences: %v\n", err)
		return 1
	}
	path := fs.Arg(0)
	if path == "" {
		path = cfg.Resolve(cfg.SBOM.Output)
	}
	bom, err := readBOM(path)
	if err != nil {
		fmt.Fprintf(stderr, "shipward licences: %v\n", err)
		return 1
	}

	file := cfg.Resolve(cfg.SBOM.Licences)
	entries, err := sbom.LoadLicences(file)
	if err != nil {
		fmt.Fprintf(stderr, "shipward licences: %v\n", err)
		return 1
	}

	var proposals []sbom.LicenceConfirmation
	var manual, drafts []string
	seen := map[string]bool{}
	for _, c := range components(bom) {
		if sbom.HasConcluded(c) {
			continue
		}
		if e := sbom.FindLicence(entries, c); e != nil && !e.IsConfirmed() {
			if !seen[e.Component] {
				seen[e.Component] = true
				drafts = append(drafts, fmt.Sprintf("%s (draft: %s)", e.Component, e.Concluded))
			}
			continue
		}
		declared := sbom.DeclaredLicence(c)
		if declared == "" || countLicences(c) > 1 || !sbom.ValidLicence(declared) {
			manual = append(manual, fmt.Sprintf("%s (declared: %s)", label(c), orNone(declared)))
			continue
		}
		_, key := sbom.ComponentKeys(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		no := false
		proposals = append(proposals, sbom.LicenceConfirmation{Component: key, Declared: declared, Concluded: declared, Confirmed: &no})
	}
	sort.Slice(proposals, func(i, j int) bool { return proposals[i].Component < proposals[j].Component })
	sort.Strings(manual)
	sort.Strings(drafts)

	if *write && len(proposals) > 0 {
		if err := appendLicences(file, proposals); err != nil {
			fmt.Fprintf(stderr, "shipward licences: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "added %d drafts (confirmed: false) to %s. Check each licence and remove its confirmed line; "+
			"shipward sbom uses only confirmed entries.\n", len(proposals), file)
	} else {
		for _, p := range proposals {
			fmt.Fprintf(stdout, "unconfirmed  %-60s declared: %s\n", p.Component, p.Declared)
		}
		if len(proposals) > 0 {
			fmt.Fprintf(stdout, "\n%d component(s) can get a draft entry with shipward licences --write (then check each one in %s).\n", len(proposals), file)
		}
	}
	if len(drafts) > 0 {
		fmt.Fprintf(stdout, "\n%d draft(s) in %s wait for a person's check (confirmed: false):\n", len(drafts), file)
		for _, d := range drafts {
			fmt.Fprintf(stdout, "  %s\n", d)
		}
	}
	if len(manual) > 0 {
		fmt.Fprintf(stdout, "\n%d component(s) need a person to find the licence and add it to %s:\n", len(manual), file)
		for _, m := range manual {
			fmt.Fprintf(stdout, "  %s\n", m)
		}
	}
	if len(proposals) == 0 && len(manual) == 0 && len(drafts) == 0 {
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
	var list yaml.Node
	if err := list.Encode(entries); err != nil {
		return err
	}
	for _, item := range list.Content {
		for i := 0; i+1 < len(item.Content); i += 2 {
			if item.Content[i].Value == "confirmed" {
				item.Content[i+1].LineComment = draftComment
			}
		}
	}
	data, err := yaml.Marshal(&list)
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
