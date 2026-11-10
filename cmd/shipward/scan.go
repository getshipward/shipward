package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/scan"
	"github.com/getshipward/shipward/internal/snapshot"
	"github.com/getshipward/shipward/internal/vex"
)

// exitFindings is the exit code when --fail-on matches. It differs from 1 (an error) so CI can tell them apart.
const exitFindings = 3

// scanFlags are the flags shipward scan and shipward triage share.
type scanFlags struct {
	cfgPath, base, trustKey string
	offline                 bool
}

func (s *scanFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.cfgPath, "config", config.DefaultFile, "path to shipward.yaml")
	fs.StringVar(&s.base, "snapshot", snapshot.DefaultURL, "snapshot URL, or a local folder with index.json")
	fs.BoolVar(&s.offline, "offline", false, "make no requests: use the cached snapshot and feeds only")
	fs.StringVar(&s.trustKey, "trust-key", "", "also accept snapshots signed with this Ed25519 public key (base64), e.g. your own copy")
}

// run loads shipward.yaml (optional when an SBOM file is given), the SBOM and the decisions, and scans.
func (s *scanFlags) run(ctx context.Context, sbomPath string) (*scan.Report, *config.Config, error) {
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) || sbomPath == "" {
			return nil, nil, err
		}
		cfg = nil
	}
	if sbomPath == "" {
		sbomPath = cfg.Resolve(cfg.SBOM.Output)
	}
	bom, err := readBOM(sbomPath)
	if err != nil {
		return nil, nil, err
	}
	var decisions []vex.Statement
	if cfg != nil {
		if decisions, err = vex.Load(cfg.Resolve(cfg.VEX.Path)); err != nil {
			return nil, nil, err
		}
	}
	rep, err := scan.Run(ctx, scan.Options{
		SBOM: sbomPath, BOM: bom, Decisions: decisions, Snapshot: s.base, Keys: trustedKeys(s.trustKey),
		Offline: s.offline, UserAgent: "shipward/" + version,
	})
	return rep, cfg, err
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf scanFlags
	sf.register(fs)
	format := fs.String("format", "text", "output: text, json or markdown")
	summary := fs.String("summary", "", `also append a Markdown summary to this file (in GitHub Actions: "$GITHUB_STEP_SUMMARY")`)
	failOn := fs.String("fail-on", "none", "exit 3 when: none, open (an advisory without a final decision) or exploited (such an advisory is known to be exploited)")
	all := fs.Bool("all", false, "name every component that could not be checked")
	var maxAge time.Duration
	fs.Func("max-age", "exit 1 when the snapshot or a feed copy is older than this (e.g. 36h, 3d); default no limit", func(v string) error {
		d, err := parseAge(v)
		maxAge = d
		return err
	})
	if err := parse(fs, args); err != nil {
		return 2
	}
	switch *format {
	case "text", "json", "markdown":
	default:
		fmt.Fprintf(stderr, "shipward scan: unknown format %q (text, json, markdown)\n", *format)
		return 2
	}
	switch *failOn {
	case "none", "open", "exploited":
	default:
		fmt.Fprintf(stderr, "shipward scan: unknown --fail-on %q (none, open, exploited)\n", *failOn)
		return 2
	}

	rep, _, err := sf.run(ctx, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "shipward scan: %v\n", err)
		return 1
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "shipward scan: %v\n", err)
			return 1
		}
	case "markdown":
		printMarkdown(stdout, rep)
	default:
		printText(stdout, rep, *all)
	}
	if *summary != "" {
		f, err := os.OpenFile(*summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintf(stderr, "shipward scan: %v\n", err)
			return 1
		}
		printMarkdown(f, rep)
		if err := f.Close(); err != nil {
			fmt.Fprintf(stderr, "shipward scan: %v\n", err)
			return 1
		}
	}
	if maxAge > 0 {
		if old := rep.OlderThan(maxAge, time.Now()); len(old) > 0 {
			fmt.Fprintf(stderr, "shipward scan: data older than --max-age %s: %s\n", maxAge, strings.Join(old, "; "))
			return 1
		}
	}
	if missing := rep.MissingExploitedFeeds(); *failOn == "exploited" && len(missing) > 0 {
		fmt.Fprintf(stderr, "shipward scan: --fail-on exploited cannot be checked: %s could not be loaded (see the warnings)\n",
			strings.Join(missing, " and "))
		return 1
	}
	for _, f := range rep.Findings {
		if f.NeedsWork() && (*failOn == "open" || (*failOn == "exploited" && f.Exploited())) {
			return exitFindings
		}
	}
	return 0
}

// parseAge reads a Go duration (36h) or a number of days (3d).
func parseAge(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a duration (36h, 3d)", s)
	}
	return d, nil
}

// reportHint is printed under an advisory that CISA or ENISA list as exploited and that has no final decision. Such a
// listing alone is not a case to report; the maker decides whether the vulnerability is actively exploited in their
// product (CRA Art. 3(42), 14(1)).
func reportHint(f scan.Finding) []string {
	purl := plainPURL(f.PURL, true)
	return []string{
		"Known to be exploited somewhere. That alone is not a case to report: decide whether it is actively exploited",
		"in your product (CRA Art. 3(42), 14(1)). If it is, the 24-hour early warning may already be due:",
		"  " + reportCommand(f.ID+" in "+f.Component, f.ID, purl),
		awareLine,
	}
}

// awareLine follows every printed report command: the command records awareness as now otherwise.
const awareLine = "  (add --aware TIME if you knew before now)"

// reportCommand is a ready shipward report new vulnerability line, every argument quoted for a POSIX shell.
func reportCommand(title, advisory, component string) string {
	return "shipward report new vulnerability --title " + shellQuote(title) + " --advisory " + shellQuote(advisory) +
		" --component " + shellQuote(component)
}

// shellQuote quotes s for a POSIX shell. Plain words (letters, digits and @%+=:,./_-) stay as they are, so the usual
// IDs and purls read normally.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// feedText says where the exploitation data came from and how old it is.
func feedText(rep *scan.Report) string {
	var parts []string
	for _, f := range rep.Feeds {
		switch {
		case !f.Used:
			parts = append(parts, f.Name+" (not available)")
		case f.Name == scan.FeedKEV:
			parts = append(parts, f.Name+" (in the snapshot)")
		case f.Date.IsZero():
			parts = append(parts, f.Name)
		default:
			parts = append(parts, fmt.Sprintf("%s (fetched %s ago)", f.Name, scan.Age(time.Since(f.Date))))
		}
	}
	return strings.Join(parts, ", ")
}

// counts returns how many findings need work and how many are closed.
func counts(rep *scan.Report) (open, closed int) {
	for _, f := range rep.Findings {
		if f.NeedsWork() {
			open++
		} else {
			closed++
		}
	}
	return open, closed
}

func facts(f scan.Finding) []string {
	var out []string
	if f.Rating != "" {
		out = append(out, "rating "+strings.ToLower(f.Rating))
	}
	if len(f.Fixed) > 0 {
		out = append(out, "fixed in "+strings.Join(f.Fixed, ", "))
	} else {
		out = append(out, "no fixed version listed")
	}
	if f.KEV != "" {
		out = append(out, "EXPLOITED (CISA KEV since "+f.KEV+")")
	}
	if f.EUVD != "" {
		out = append(out, "EXPLOITED (ENISA "+f.EUVD+")")
	}
	if f.EPSS != nil {
		out = append(out, fmt.Sprintf("EPSS %.1f%%", f.EPSS.Score*100))
	}
	return out
}

func decisionText(f scan.Finding) string {
	d := f.Decision
	if d == nil {
		return "none yet"
	}
	parts := []string{strings.ReplaceAll(d.Status, "_", " ")}
	for _, s := range []string{strings.ReplaceAll(d.Justification, "_", " "), d.Impact, d.Action} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	who := d.Date
	if d.By != "" {
		who = d.By + ", " + d.Date
	}
	return strings.Join(parts, ": ") + " (" + who + ")"
}

func printText(w io.Writer, rep *scan.Report, all bool) {
	fmt.Fprintf(w, "%s: %d components checked against the vulnerability snapshot of %s (%s old)\n", rep.SBOM, rep.Checked,
		rep.Snapshot.Format("2006-01-02 15:04 MST"), scan.Age(time.Since(rep.Snapshot)))
	for _, warn := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	fmt.Fprintln(w)
	for _, f := range rep.Findings {
		ids := f.ID
		if len(f.Aliases) > 0 {
			ids += " (" + strings.Join(f.Aliases, ", ") + ")"
		}
		fmt.Fprintf(w, "%s  %s\n", f.Component, ids)
		if f.Summary != "" {
			fmt.Fprintf(w, "    %s\n", f.Summary)
		}
		fmt.Fprintf(w, "    %s\n    decision: %s\n    %s\n", strings.Join(facts(f), "; "), decisionText(f), f.URL)
		if f.Exploited() && f.NeedsWork() {
			for _, line := range reportHint(f) {
				fmt.Fprintf(w, "    %s\n", line)
			}
		}
		fmt.Fprintln(w)
	}

	open, closed := counts(rep)
	if open+closed == 0 {
		fmt.Fprintln(w, "No advisory in the snapshot names these component versions.")
	} else {
		fmt.Fprintf(w, "Advisories that name these component versions: %d. Need a decision or work: %d. Decided: %d.\n", open+closed, open, closed)
	}
	if open > 0 {
		fmt.Fprintln(w, "Record decisions with shipward triage.")
	}
	if len(rep.Unused) > 0 {
		fmt.Fprintf(w, "%d decision(s) in vex.yaml match no advisory now (shipward triage lists them).\n", len(rep.Unused))
	}
	if len(rep.NotChecked) > 0 {
		fmt.Fprintf(w, "Not checked (no package URL of a known ecosystem): %s\n", listNames(rep.NotChecked, all))
	}
	fmt.Fprintln(w, "An advisory that names a version does not prove the product is affected: a person decides that.")
	fmt.Fprintf(w, "Exploitation data: %s.\n", feedText(rep))
	if len(rep.Sources) > 0 {
		fmt.Fprintf(w, "Data: %s.\n", sourceNames(rep.Sources))
	}
}

func printMarkdown(w io.Writer, rep *scan.Report) {
	open, closed := counts(rep)
	fmt.Fprintf(w, "### Vulnerability scan\n\n")
	fmt.Fprintf(w, "%d components checked against the snapshot of %s (%s old). ", rep.Checked,
		rep.Snapshot.Format("2006-01-02 15:04 MST"), scan.Age(time.Since(rep.Snapshot)))
	if open+closed == 0 {
		fmt.Fprintf(w, "No advisory names these component versions.\n\n")
	} else {
		fmt.Fprintf(w, "Advisories: %d. Need a decision or work: **%d**. Decided: %d.\n\n", open+closed, open, closed)
	}
	for _, warn := range rep.Warnings {
		fmt.Fprintf(w, "> Warning: %s\n\n", md(warn))
	}
	if len(rep.Findings) > 0 {
		fmt.Fprintln(w, "| Component | Advisory | Rating | Fixed in | Exploited | EPSS | Decision |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
		for _, f := range rep.Findings {
			var exploited []string
			if f.KEV != "" {
				exploited = append(exploited, "KEV")
			}
			if f.EUVD != "" {
				exploited = append(exploited, "EUVD")
			}
			ex := ""
			if len(exploited) > 0 {
				ex = "**yes** (" + strings.Join(exploited, ", ") + ")"
			}
			epss := ""
			if f.EPSS != nil {
				epss = fmt.Sprintf("%.1f%%", f.EPSS.Score*100)
			}
			fmt.Fprintf(w, "| `%s` | [%s](%s) %s | %s | %s | %s | %s | %s |\n", md(f.Component), md(f.ID), f.URL,
				md(f.Summary), strings.ToLower(f.Rating), md(strings.Join(f.Fixed, ", ")), ex, epss, md(decisionText(f)))
		}
		fmt.Fprintln(w)
	}
	exploited := 0
	for _, f := range rep.Findings {
		if f.Exploited() && f.NeedsWork() {
			exploited++
		}
	}
	if exploited > 0 {
		fmt.Fprintf(w, "Known to be exploited somewhere, without a final decision: **%d**. That alone is not a case to report: "+
			"decide for each whether it is actively exploited in your product (CRA Art. 3(42), 14(1)). If it is, the 24-hour "+
			"early warning may already be due: `shipward report new vulnerability` (`shipward scan` prints the full command).\n\n", exploited)
	}
	if len(rep.Unused) > 0 {
		fmt.Fprintf(w, "%d decision(s) in vex.yaml match no advisory now.\n\n", len(rep.Unused))
	}
	if len(rep.NotChecked) > 0 {
		fmt.Fprintf(w, "Not checked (no package URL of a known ecosystem): %d components.\n\n", len(rep.NotChecked))
	}
	fmt.Fprintf(w, "An advisory that names a version does not prove the product is affected: a person decides that. "+
		"Exploitation data: %s. Data: %s.\n\n", md(feedText(rep)), md(sourceNames(rep.Sources)))
}

// md makes text safe inside a Markdown table cell.
func md(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "\r", "", "<", "&lt;", ">", "&gt;").Replace(s)
}

func listNames(names []string, all bool) string {
	if all || len(names) <= maxListed {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, +%d more (--all lists them)", strings.Join(names[:maxListed], ", "), len(names)-maxListed)
}

func sourceNames(sources []snapshot.Source) string {
	var names []string
	for _, s := range sources {
		names = append(names, s.Name+" ("+s.Licence+")")
	}
	return strings.Join(names, ", ")
}

func trustedKeys(extra string) []string {
	keys := append([]string(nil), snapshot.TrustedKeys...)
	if extra != "" {
		keys = append(keys, extra)
	}
	return keys
}
