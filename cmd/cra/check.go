package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/getshipward/shipward/internal/check"
	"github.com/getshipward/shipward/internal/config"
)

// maxListed is how many failing components are named per rule; the rest are counted.
const maxListed = 5

func runCheck(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "sbom" {
		fmt.Fprintln(stderr, "usage: cra check sbom [--profile bsi] [file]")
		return 2
	}
	fs := flag.NewFlagSet("check sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "bsi", "rule set: bsi (BSI TR-03183-2 v2.1.0)")
	cfgPath := fs.String("config", config.DefaultFile, "path to cra.yaml (used when no file is given)")
	all := fs.Bool("all", false, "name every failing component, not only the first few")
	summary := fs.String("summary", "", `also append the result to this Markdown file (in GitHub Actions: "$GITHUB_STEP_SUMMARY")`)
	if err := parse(fs, args[1:]); err != nil {
		return 2
	}
	if *profile != "bsi" {
		fmt.Fprintf(stderr, "cra check sbom: unknown profile %q (known: bsi)\n", *profile)
		return 2
	}

	path := fs.Arg(0)
	if path == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(stderr, "cra check sbom: no file given and %v\n", err)
			return 1
		}
		path = cfg.Resolve(cfg.SBOM.Output)
	}
	bom, err := readBOM(path)
	if err != nil {
		fmt.Fprintf(stderr, "cra check sbom: %v\n", err)
		return 1
	}

	results := check.BSI(bom)
	limit := maxListed
	if *all {
		limit = -1
	}
	printResults(stdout, path, results, limit)
	if *summary != "" {
		if err := appendSummary(*summary, path, results); err != nil {
			fmt.Fprintf(stderr, "cra check sbom: %v\n", err)
			return 1
		}
	}
	for _, r := range results {
		if r.Level == check.Must && !r.OK() {
			return 1
		}
	}
	return 0
}

func readBOM(path string) (*cyclonedx.BOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(f, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &bom, nil
}

func printResults(w io.Writer, path string, results []check.Result, limit int) {
	fmt.Fprintf(w, "%s: %s\n\n", check.BSIProfile, path)
	var mustFailed, gaps int
	for _, r := range results {
		status := "ok"
		if !r.OK() {
			if r.Total == 1 {
				status = "missing"
			} else {
				status = fmt.Sprintf("%d of %d", r.Passed, r.Total)
			}
			if r.Level == check.Must {
				mustFailed++
			} else {
				gaps++
			}
		}
		fmt.Fprintf(w, "%-9s %-62s %s\n", r.Level, r.Title, status)
		if !r.OK() {
			fmt.Fprintf(w, "          %s\n", listFailing(r.Failing, limit))
		}
	}
	fmt.Fprintln(w)
	switch {
	case mustFailed == 0 && gaps == 0:
		fmt.Fprintln(w, "All checked fields are present.")
	case mustFailed == 0:
		fmt.Fprintf(w, "All required fields are present; %d rule(s) for information that exists have gaps.\n", gaps)
	default:
		fmt.Fprintf(w, "%d required rule(s) not met, %d rule(s) for information that exists have gaps.\n", mustFailed, gaps)
	}
	fmt.Fprintln(w, "This lists missing fields. It is not a certification and not legal advice.")
}

// appendSummary adds a Markdown table of the rules to a job summary.
func appendSummary(file, path string, results []check.Result) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "### SBOM fields (%s)\n\n| Level | Field | Status |\n|---|---|---|\n", check.BSIProfile)
	for _, r := range results {
		status := "ok"
		if !r.OK() {
			status = fmt.Sprintf("**%d of %d**", r.Passed, r.Total)
			if r.Total == 1 {
				status = "**missing**"
			}
		}
		fmt.Fprintf(f, "| %s | %s | %s |\n", r.Level, md(r.Title), status)
	}
	fmt.Fprintln(f, "\nThis lists missing fields. It is not a certification and not legal advice.")
	fmt.Fprintln(f)
	return f.Close()
}

func listFailing(names []string, limit int) string {
	if limit < 0 || len(names) <= limit {
		return "missing: " + strings.Join(names, ", ")
	}
	return fmt.Sprintf("missing: %s, +%d more (--all lists them)", strings.Join(names[:limit], ", "), len(names)-limit)
}
