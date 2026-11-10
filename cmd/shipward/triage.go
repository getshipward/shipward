package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/anchore/packageurl-go"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/scan"
	"github.com/getshipward/shipward/internal/snapshot"
	"github.com/getshipward/shipward/internal/vex"
)

const triageUsage = `usage:
  shipward triage [list] [flags] [sbom]          advisories without a final decision, and decisions no advisory needs
  shipward triage set ID PURL --status S [flags] record a decision in vex.yaml
  shipward triage export [-o file] [flags] [sbom] write vex.yaml as OpenVEX (default sbom/vex.openvex.json)

statuses: not_affected (needs --justification or --impact), affected (needs --action), fixed (record --fixed-in and
  --advisory once the advisory is published), under_investigation
flags of set: --by WHO (recommended), --date (YYYY-MM-DD or RFC 3339), --all-versions;
  --upstream-reported DATE --upstream-link URL --upstream-fix-shared[=false]: what you told the component's maintainer
  (CRA Art. 13(6)); each flag changes only its own field, the others are kept
justifications: ` + "component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path,\n  vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist\n"

func runTriage(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "list", "set", "export":
			sub, args = args[0], args[1:]
		case "help":
			fmt.Fprint(stdout, triageUsage)
			return 0
		}
	}
	switch sub {
	case "set":
		return triageSet(ctx, args, stdout, stderr)
	case "export":
		return triageExport(ctx, args, stdout, stderr)
	}
	return triageList(ctx, args, stdout, stderr)
}

func triageList(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf scanFlags
	sf.register(fs)
	if err := parse(fs, args); err != nil {
		return 2
	}
	rep, cfg, err := sf.run(ctx, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage: %v\n", err)
		return 1
	}
	vexPath := "vex.yaml"
	if cfg != nil {
		vexPath = cfg.VEX.Path
	}

	n := 0
	for _, f := range rep.Findings {
		if !f.NeedsWork() {
			continue
		}
		n++
		fmt.Fprintf(stdout, "%s  %s  %s\n", f.Component, f.ID, f.Summary)
		fmt.Fprintf(stdout, "    %s\n    now: %s\n", strings.Join(facts(f), "; "), decisionText(f))
		if f.Exploited() {
			for _, line := range reportHint(f) {
				fmt.Fprintf(stdout, "    %s\n", line)
			}
		}
		if d := f.Decision; d != nil && d.Status == vex.Affected && d.Upstream == nil {
			fmt.Fprintln(stdout, "    upstream: not recorded. If the component's maintainer does not know of it yet, tell them (CRA Art. 13(6); see shipward triage help)")
		}
		fmt.Fprintf(stdout, "    shipward triage set %s %s --status not_affected --justification ... --impact \"...\"\n\n", f.ID, plainPURL(f.PURL, true))
	}
	if n == 0 {
		fmt.Fprintln(stdout, "No advisory needs a decision.")
	} else {
		fmt.Fprintf(stdout, "Advisories that need a decision or work: %d. Decide each one (see shipward triage help), then commit %s.\n", n, vexPath)
	}
	if cfg != nil {
		printNeedsAdvisory(stdout, cfg)
	}
	if len(rep.Unused) > 0 {
		fmt.Fprintf(stdout, "\nThese decisions in %s match no advisory of this SBOM (the component was updated or removed). Remove them when you no longer need them:\n", vexPath)
		for _, s := range rep.Unused {
			fmt.Fprintf(stdout, "  %s %s (%s, %s)\n", s.ID, s.Component, s.Status, s.Date)
		}
	}
	return 0
}

// printNeedsAdvisory lists fixed decisions that do not record the update and the published advisory yet. They are
// final for VEX, but the CRA asks for an advisory about every fixed vulnerability (Annex I Part II(4), (8)).
func printNeedsAdvisory(w io.Writer, cfg *config.Config) {
	decisions, err := vex.Load(cfg.Resolve(cfg.VEX.Path))
	if err != nil {
		return // triage list loaded the same file already
	}
	var open []vex.Statement
	for _, s := range decisions {
		if s.NeedsAdvisory() {
			open = append(open, s)
		}
	}
	if len(open) == 0 {
		return
	}
	fmt.Fprintf(w, "\nFixed, but the update or the advisory is not recorded yet (CRA Annex I Part II(4), (8)): %d.\n", len(open))
	fmt.Fprintln(w, "If your product was affected, publish an advisory with the update (shipward advisory new ID), then record it:")
	for _, s := range open {
		fixed := s.FixedIn
		if fixed == "" {
			fixed = "VERSION"
		}
		fmt.Fprintf(w, "  shipward triage set %s %s --status fixed --fixed-in %s --advisory URL\n", s.ID, s.Component, fixed)
	}
}

// plainPURL drops qualifiers and subpath (and the version, for every version), the form vex.yaml uses. The name keeps
// its case.
func plainPURL(s string, withVersion bool) string {
	p, err := packageurl.FromString(s)
	if err != nil {
		return s
	}
	p.Qualifiers, p.Subpath = nil, ""
	if !withVersion {
		p.Version = ""
	}
	return p.ToString()
}

func triageSet(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("triage set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	status := fs.String("status", "", "not_affected, affected, fixed or under_investigation")
	justification := fs.String("justification", "", "why it is not_affected (see shipward triage help)")
	impact := fs.String("impact", "", "not_affected: how the product avoids it, in your words")
	action := fs.String("action", "", "affected: what users should do")
	by := fs.String("by", "", "who decided (a name or role; recommended)")
	fixedIn := fs.String("fixed-in", "", "fixed: the product version with the security update")
	advisoryAt := fs.String("advisory", "", "fixed: where the advisory about it is published (URL)")
	date := fs.String("date", time.Now().Format(time.DateOnly), "date or time of the decision (YYYY-MM-DD or RFC 3339)")
	upReported := fs.String("upstream-reported", "", "when you reported it to the component's maintainer (YYYY-MM-DD; CRA Art. 13(6))")
	upLink := fs.String("upstream-link", "", "link to that report, issue or advisory")
	upFix := fs.Bool("upstream-fix-shared", false, "you shared your fix (code or documentation) with the maintainer")
	allVersions := fs.Bool("all-versions", false, "apply to every version of the component, not only this one")
	sf := scanFlags{offline: true} // affected: look the advisory up in the cached snapshot, without a request
	fs.StringVar(&sf.base, "snapshot", snapshot.DefaultURL, "snapshot URL or folder whose cached copy says whether the advisory is known to be exploited")
	fs.StringVar(&sf.trustKey, "trust-key", "", "also accept snapshots signed with this Ed25519 public key (base64)")
	if err := parse(fs, args); err != nil {
		return 2
	}
	pos := fs.Args()
	if len(pos) != 2 || *status == "" {
		fmt.Fprint(stderr, triageUsage)
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage set: %v\n", err)
		return 1
	}
	component := plainPURL(pos[1], !*allVersions)
	s := vex.Statement{ID: pos[0], Component: component, Status: *status, Justification: *justification,
		Impact: *impact, Action: *action, By: *by, Date: *date, FixedIn: *fixedIn, Advisory: *advisoryAt}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	path := cfg.Resolve(cfg.VEX.Path)
	existing, err := vex.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage set: fix %s first: %v\n", path, err)
		return 1
	}
	// A new decision on the same advisory and component keeps what was told upstream; the upstream flags given now
	// change only their own fields.
	var up vex.Upstream
	for _, old := range existing {
		if old.ID == s.ID && old.Component == s.Component && old.Upstream != nil {
			up = *old.Upstream
		}
	}
	if given["upstream-reported"] {
		up.Reported = *upReported
	}
	if given["upstream-link"] {
		up.Link = *upLink
	}
	if given["upstream-fix-shared"] {
		up.FixShared = *upFix
	}
	if up != (vex.Upstream{}) {
		s.Upstream = &up
	}
	if err := vex.Set(path, s); err != nil {
		fmt.Fprintf(stderr, "shipward triage set: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "recorded %s for %s on %s in %s\n", s.Status, s.ID, s.Component, path)
	if s.By == "" {
		fmt.Fprintln(stderr, "warning: no --by: record who decided (a name or role), so the decision can be traced later")
	}
	if s.NeedsAdvisory() {
		fmt.Fprintln(stdout, "If your product was affected, the CRA asks for an advisory once the update is out (Annex I Part II(4)):")
		fmt.Fprintf(stdout, "shipward advisory new %s, then record --fixed-in and --advisory here.\n", s.ID)
	}
	if s.Status == vex.Affected {
		sf.cfgPath = *cfgPath
		affectedHint(ctx, stdout, sf, s)
	}
	if s.Status == vex.Affected && s.Upstream == nil {
		fmt.Fprintln(stdout, upstreamHint)
	}
	return 0
}

// affectedHint looks the advisory up in the cached snapshot (no request) and, when CISA or ENISA list it as
// exploited, says what that means for reporting (CRA Art. 14). When the lookup cannot tell (no cached snapshot, no
// finding for this advisory, or an exploitation list missing), it says so and gives the same guidance.
func affectedHint(ctx context.Context, w io.Writer, sf scanFlags, s vex.Statement) {
	rep, _, err := sf.run(ctx, "")
	why := ""
	switch {
	case err != nil:
		why = err.Error()
	default:
		found := false
		for _, f := range rep.Findings {
			if vex.Find([]vex.Statement{s}, f.IDs(), f.PURL) == nil {
				continue
			}
			found = true
			if f.Exploited() {
				for _, line := range reportHint(f) {
					fmt.Fprintln(w, line)
				}
				return
			}
		}
		if missing := rep.MissingExploitedFeeds(); !found {
			why = "the cached snapshot has no advisory " + s.ID + " for " + s.Component
		} else if len(missing) > 0 {
			why = strings.Join(missing, " and ") + " could not be loaded"
		} else {
			return // both lists were checked and neither names it
		}
	}
	fmt.Fprintf(w, "Could not check whether %s is known to be exploited (%s). Decide whether it is actively exploited\n"+
		"in your product (CRA Art. 3(42), 14(1)). If it is, the 24-hour early warning may already be due:\n  %s\n%s\n",
		s.ID, why, reportCommand(s.ID+" in "+s.Component, s.ID, s.Component), awareLine)
}

// upstreamHint follows an affected decision without upstream fields (CRA Art. 13(6)).
const upstreamHint = "If the component's maintainer does not know of it yet, report it to them, and share your fix if you made one\n" +
	"(CRA Art. 13(6)). Record it with --upstream-reported DATE --upstream-link URL [--upstream-fix-shared]."

func triageExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("triage export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	out := fs.String("o", "", `output file, or "-" for stdout (default vex.output in shipward.yaml)`)
	offline := fs.Bool("offline", true, "use the cached snapshot for the advisories' aliases (false: fetch a new one)")
	if err := parse(fs, args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage export: %v\n", err)
		return 1
	}
	sbomPath := fs.Arg(0)
	if sbomPath == "" {
		sbomPath = cfg.Resolve(cfg.SBOM.Output)
	}
	bom, err := readBOM(sbomPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage export: %v\n", err)
		return 1
	}
	decisions, err := vex.Load(cfg.Resolve(cfg.VEX.Path))
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage export: %v\n", err)
		return 1
	}

	// The advisories' other IDs come from the snapshot; without one the document simply has no aliases.
	aliases := map[string][]string{}
	sf := scanFlags{cfgPath: *cfgPath, base: snapshot.DefaultURL, offline: *offline}
	if rep, _, err := sf.run(ctx, sbomPath); err == nil {
		for _, f := range rep.Findings {
			if f.Decision != nil {
				for _, id := range f.IDs() {
					if id != f.Decision.ID {
						aliases[f.Decision.ID] = appendNew(aliases[f.Decision.ID], id)
					}
				}
			}
		}
	} else {
		fmt.Fprintf(stderr, "shipward triage export: no aliases (%v)\n", err)
	}

	var targets []string
	for _, c := range scan.Components(bom) {
		if c.PackageURL != "" {
			targets = append(targets, c.PackageURL)
		}
	}
	author := cfg.Manufacturer.Name
	if cfg.Manufacturer.Email != "" {
		author += " <" + cfg.Manufacturer.Email + ">"
	}
	target := cfg.Resolve(cfg.VEX.Output)
	if *out != "" {
		target = *out
	}
	// The document written before, for its version: an unchanged result keeps it, a changed one gets the next.
	var prev *vex.Document
	prevPath := target
	if target == "-" {
		prevPath = cfg.Resolve(cfg.VEX.Output)
	}
	if data, err := os.ReadFile(prevPath); err == nil {
		var d vex.Document
		if json.Unmarshal(data, &d) == nil {
			prev = &d
		}
	}
	if prev == nil && target != "-" {
		fmt.Fprintf(stderr, "shipward triage export: no earlier document at %s: this one starts at version 1 (keep the file to keep the count)\n", prevPath)
	}
	doc, err := vex.Export(author, "shipward "+version, productID(bom, cfg), decisions, targets, aliases, prev, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "shipward triage export: %v\n", err)
		return 1
	}
	write := func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(doc)
	}
	if target == "-" {
		if err := write(stdout); err != nil {
			fmt.Fprintf(stderr, "shipward triage export: %v\n", err)
			return 1
		}
		return 0
	}
	if err := writeFile(target, write); err != nil {
		fmt.Fprintf(stderr, "shipward triage export: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (%d statements, version %d)\n", target, len(doc.Statements), doc.Version)
	return 0
}

// productID names the product in VEX with an ID that stays the same on every run for the same release: the SBOM's
// product purl when it has one, else a generic purl of the product name and version (pkg:generic/<name>@<version>).
// The SBOM's serial number is not used: it changes with every shipward sbom run.
func productID(bom *cyclonedx.BOM, cfg *config.Config) string {
	name, ver := cfg.Product.Name, cfg.Product.Version
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		c := bom.Metadata.Component
		if c.PackageURL != "" {
			// One document per release: a purl without a version gets the product's.
			if p, err := packageurl.FromString(c.PackageURL); err == nil && p.Version == "" && c.Version != "" {
				p.Version = c.Version
				return p.ToString()
			}
			return c.PackageURL
		}
		if c.Name != "" {
			name, ver = c.Name, c.Version
		}
	}
	return packageurl.NewPackageURL("generic", "", name, ver, nil, "").ToString()
}

func appendNew(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
