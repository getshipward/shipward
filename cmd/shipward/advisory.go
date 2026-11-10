package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getshipward/shipward/internal/advisory"
	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/scan"
	"github.com/getshipward/shipward/internal/snapshot"
	"github.com/getshipward/shipward/internal/vex"
)

const advisoryUsage = `usage:
  shipward advisory new ID [flags]   write a draft advisory about a fixed vulnerability (CRA Annex I Part II(4))

ID is the vulnerability's ID: a CVE, GHSA or EUVD ID, or your own (EXAMPLE-2026-001). shipward fills in what it knows
from vex.yaml and the cached vulnerability snapshot; the rest is TODO. Flags:
  --title T            a short title
  --affected V         an affected product version; repeat for more
  --fixed-in V         the product version with the security update
  --component PURL     the affected component, when the flaw is in a dependency
  --severity S         for example high
  --description TEXT, --impact TEXT, --remediation TEXT
  --csaf               also write a CSAF 2.0 document (needs --affected, --fixed-in and manufacturer.url)
  --force              overwrite drafts that exist
  -o DIR               output folder (default <docs.dir>/advisories)

When it is published, record it: shipward triage set ID PURL --status fixed --fixed-in V --advisory URL
`

func runAdvisory(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, advisoryUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "new" {
		fmt.Fprintf(stderr, "shipward advisory: unknown command %q\n\n%s", args[0], advisoryUsage)
		return 2
	}
	return advisoryNew(ctx, args[1:], stdout, stderr, time.Now())
}

func advisoryNew(ctx context.Context, args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("advisory new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	title := fs.String("title", "", "a short title")
	fixedIn := fs.String("fixed-in", "", "the product version with the security update")
	component := fs.String("component", "", "the affected component (purl)")
	severity := fs.String("severity", "", "the severity, for example high")
	description := fs.String("description", "", "what the vulnerability is")
	impact := fs.String("impact", "", "what an attacker can do")
	remediation := fs.String("remediation", "", "what users should do (default: update to --fixed-in)")
	withCSAF := fs.Bool("csaf", false, "also write a CSAF 2.0 document")
	force := fs.Bool("force", false, "overwrite drafts that exist")
	outDir := fs.String("o", "", "output folder (default <docs.dir>/advisories)")
	offline := fs.Bool("offline", true, "use the cached snapshot for the advisory's summary and IDs (false: fetch a new one)")
	var affected stringList
	fs.Var(&affected, "affected", "an affected product version; repeat for more")
	if err := parse(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, advisoryUsage)
		return 2
	}
	id := fs.Arg(0)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward advisory new: %v\n", err)
		return 1
	}
	a := advisory.Advisory{ID: id, Title: *title, Product: cfg.Product.Name, Manufacturer: cfg.Manufacturer.Name,
		Namespace: cfg.Manufacturer.URL, Contact: strings.TrimPrefix(cfg.Security.Contact, "mailto:"),
		Affected: affected, FixedIn: *fixedIn, Component: *component, Severity: *severity, Description: *description,
		Impact: *impact, Remediation: *remediation, Date: now, Tool: "shipward " + version}

	// What the maker decided (vex.yaml) and what the snapshot knows about a component's advisory.
	decisions, err := vex.Load(cfg.Resolve(cfg.VEX.Path))
	if err != nil {
		fmt.Fprintf(stderr, "shipward advisory new: %v\n", err)
		return 1
	}
	var finding *scan.Finding
	if _, err := os.Stat(cfg.Resolve(cfg.SBOM.Output)); err == nil {
		sf := scanFlags{cfgPath: *cfgPath, base: snapshot.DefaultURL, offline: *offline}
		if rep, _, err := sf.run(ctx, ""); err == nil {
			for i, f := range rep.Findings {
				if contains(f.IDs(), id) {
					finding = &rep.Findings[i]
					break
				}
			}
		}
	}
	fillAdvisory(&a, decisions, finding)

	dir := cfg.Resolve(filepath.Join(cfg.Docs.Dir, "advisories"))
	if *outDir != "" {
		dir = *outDir
	}
	base := filepath.Join(dir, advisory.FileName(id))
	type file struct {
		path   string
		render func(advisory.Advisory) ([]byte, error)
	}
	files := []file{{base + ".md", advisory.Markdown}}
	if *withCSAF {
		files = append(files, file{base + ".csaf.json", advisory.CSAF})
	}
	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil && !*force {
			fmt.Fprintf(stderr, "shipward advisory new: %s exists; --force overwrites it\n", f.path)
			return 1
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "shipward advisory new: %v\n", err)
			return 1
		}
	}
	for _, f := range files {
		body, err := f.render(a)
		if err != nil {
			fmt.Fprintf(stderr, "shipward advisory new: %v\n", err)
			return 2
		}
		if err := writeFile(f.path, func(w io.Writer) error { _, err := w.Write(body); return err }); err != nil {
			fmt.Fprintf(stderr, "shipward advisory new: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s\n", f.path)
	}
	fmt.Fprintln(stdout, "\nComplete the TODOs, then publish it with the security update (CRA Annex I Part II(4), (8)).")
	fmt.Fprintln(stdout, "Until the update is out, it describes an unfixed flaw: keep it out of public repositories.")
	purl := a.Component
	if purl == "" {
		purl = "PURL"
	}
	fixed := a.FixedIn
	if fixed == "" {
		fixed = "VERSION"
	}
	fmt.Fprintf(stdout, "When it is published: shipward triage set %s %s --status fixed --fixed-in %s --advisory URL\n", id, purl, fixed)
	return 0
}

// fillAdvisory completes the advisory from the decisions in vex.yaml and the snapshot's finding, without replacing what
// the flags set.
func fillAdvisory(a *advisory.Advisory, decisions []vex.Statement, f *scan.Finding) {
	ids := []string{a.ID}
	if f != nil {
		ids = f.IDs()
	}
	for _, s := range decisions {
		if !contains(ids, s.ID) {
			continue
		}
		if a.Component == "" {
			a.Component = s.Component
		}
		if a.FixedIn == "" {
			a.FixedIn = s.FixedIn
		}
		if a.Remediation == "" && s.Action != "" {
			a.Remediation = s.Action
		}
	}
	if f == nil {
		return
	}
	for _, id := range f.IDs() {
		if id != a.ID {
			a.Aliases = append(a.Aliases, id)
		}
	}
	if a.Component == "" {
		a.Component = plainPURL(f.PURL, true)
	}
	if a.Description == "" && f.Summary != "" {
		a.Description = f.Summary + " (in the component " + f.Component + ")."
	}
	if a.Severity == "" {
		a.Severity = f.Rating
	}
	if a.CVSS == "" {
		a.CVSS = f.CVSS
	}
	if f.URL != "" {
		a.References = append(a.References, f.URL)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
