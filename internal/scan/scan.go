// Package scan matches an SBOM against the vulnerability snapshot and the maker's VEX decisions, on the maker's
// machine.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/getshipward/shipward/internal/osv"
	"github.com/getshipward/shipward/internal/snapshot"
	"github.com/getshipward/shipward/internal/vex"
)

// States of a finding: no decision yet, or the decision's status.
const (
	StateOpen = "open"
)

// Finding is one advisory that names a component's version.
type Finding struct {
	Component string   `json:"component"` // name@version
	PURL      string   `json:"purl"`
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Rating    string   `json:"rating,omitempty"`
	CVSS      string   `json:"cvss,omitempty"`
	Fixed     []string `json:"fixed,omitempty"`
	URL       string   `json:"url"`
	// Exploited in the wild, per CISA KEV and/or ENISA EUVD (date or ID), and FIRST's EPSS.
	KEV  string         `json:"kev,omitempty"`
	EUVD string         `json:"euvd,omitempty"`
	EPSS *snapshot.EPSS `json:"epss,omitempty"`
	// State is "open" (no decision) or the status of the decision in vex.yaml.
	State    string         `json:"state"`
	Decision *vex.Statement `json:"decision,omitempty"`
}

// Exploited reports whether CISA or ENISA list the advisory as exploited.
func (f Finding) Exploited() bool { return f.KEV != "" || f.EUVD != "" }

// NeedsWork reports whether the finding has no final decision (open, under investigation, or affected).
func (f Finding) NeedsWork() bool { return !vex.Final(f.State) }

// IDs returns the advisory ID and its aliases.
func (f Finding) IDs() []string { return append([]string{f.ID}, f.Aliases...) }

// Report is the result of one scan.
type Report struct {
	SBOM       string            `json:"sbom"`
	Snapshot   time.Time         `json:"snapshot"`
	Warnings   []string          `json:"warnings,omitempty"`
	Checked    int               `json:"checked"`
	NotChecked []string          `json:"not_checked,omitempty"`
	Findings   []Finding         `json:"findings"`
	Unused     []vex.Statement   `json:"unused_decisions,omitempty"`
	Sources    []snapshot.Source `json:"sources"`
}

// Options configure a scan.
type Options struct {
	SBOM      string // path, for the report
	BOM       *cyclonedx.BOM
	Decisions []vex.Statement
	Snapshot  string // URL or local folder
	Keys      []string
	Offline   bool
	UserAgent string
	CacheDir  string // default snapshot.DefaultCacheDir()
}

type target struct {
	label, purl, version string
	pkg                  osv.Package
}

// Run scans the SBOM.
func Run(ctx context.Context, o Options) (*Report, error) {
	cache := o.CacheDir
	if cache == "" {
		cache = snapshot.DefaultCacheDir()
	}
	var targets []target
	var notChecked []string
	ecosystems := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range Components(o.BOM) {
		p, v, ok := osv.FromPURL(c.PackageURL)
		if !ok {
			notChecked = append(notChecked, Label(c))
			continue
		}
		key := osv.Key(p) + "@" + v
		if seen[key] {
			continue // the same package from several lock files
		}
		seen[key] = true
		targets = append(targets, target{label: Label(c), purl: c.PackageURL, version: v, pkg: p})
		ecosystems[p.Ecosystem] = true
	}
	sort.Strings(notChecked)

	var ecoList []string
	for e := range ecosystems {
		ecoList = append(ecoList, e)
	}
	sort.Strings(ecoList)
	client := &snapshot.Client{
		HTTP:      &http.Client{Timeout: 5 * time.Minute},
		Base:      o.Snapshot,
		CacheDir:  filepath.Join(cache, "snapshot", hash(o.Snapshot)),
		Keys:      o.Keys,
		UserAgent: o.UserAgent,
		Offline:   o.Offline,
	}
	data, err := client.Load(ctx, ecoList)
	if err != nil {
		return nil, err
	}

	// Records by package, so each component looks only at its own.
	byPackage := map[string][]*osv.Vulnerability{}
	for _, vulns := range data.Vulns {
		for i := range vulns {
			v := &vulns[i]
			done := map[string]bool{}
			for _, a := range v.Affected {
				k := osv.Key(a.Package)
				if !done[k] {
					done[k] = true
					byPackage[k] = append(byPackage[k], v)
				}
			}
		}
	}

	rep := &Report{SBOM: o.SBOM, Snapshot: data.Index.Created, Checked: len(targets), NotChecked: notChecked,
		Findings: []Finding{}, Sources: data.Index.Sources}
	if data.Warning != "" {
		rep.Warnings = append(rep.Warnings, data.Warning)
	}
	type match struct {
		t target
		v *osv.Vulnerability
	}
	var matches []match
	cves := map[string]bool{}
	for _, t := range targets {
		for _, v := range byPackage[osv.Key(t.pkg)] {
			if v.Affects(t.pkg, t.version) {
				matches = append(matches, match{t, v})
				for _, c := range v.CVEs() {
					cves[c] = true
				}
			}
		}
	}

	// ENISA's list and EPSS come from the sources themselves, not from the snapshot (snapshot.Live).
	live := (&snapshot.Live{
		Fetcher:  &snapshot.Fetcher{HTTP: client.HTTP, UserAgent: client.UserAgent},
		CacheDir: filepath.Join(cache, "live"),
		EUVDURL:  snapshot.EUVDURL,
		EPSSURL:  snapshot.EPSSURL,
		MaxAge:   20 * time.Hour,
		Now:      time.Now,
		Offline:  o.Offline,
	}).Load(ctx, cves)
	rep.Warnings = append(rep.Warnings, live.Warnings...)
	data.Exploited.EUVD, data.Exploited.EPSS = live.EUVD, live.EPSS
	rep.Sources = append(rep.Sources, snapshot.LiveSources...)

	used := map[*vex.Statement]bool{}
	for _, m := range matches {
		f := newFinding(m.t, m.v, data.Exploited)
		if d := vex.Find(o.Decisions, f.IDs(), f.PURL); d != nil {
			f.State, f.Decision = d.Status, d
			used[d] = true
		}
		rep.Findings = append(rep.Findings, f)
	}
	for i := range o.Decisions {
		if !used[&o.Decisions[i]] {
			rep.Unused = append(rep.Unused, o.Decisions[i])
		}
	}
	sortFindings(rep.Findings)
	return rep, nil
}

func newFinding(t target, v *osv.Vulnerability, ex snapshot.Exploited) Finding {
	f := Finding{Component: t.label, PURL: t.purl, ID: v.ID, Aliases: v.Aliases, Summary: v.Summary, Rating: v.Rating,
		Fixed: v.Fixed(t.pkg), URL: v.URL, State: StateOpen}
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_") && f.CVSS == "" {
			f.CVSS = s.Score
		}
	}
	for _, cve := range v.CVEs() {
		if k, ok := ex.KEV[cve]; ok && f.KEV == "" {
			f.KEV = k.Added
		}
		if e, ok := ex.EUVD[cve]; ok && f.EUVD == "" {
			f.EUVD = e.ID
		}
		if s, ok := ex.EPSS[cve]; ok && (f.EPSS == nil || s.Score > f.EPSS.Score) {
			f.EPSS = &s
		}
	}
	return f
}

// rank orders states: affected first, then open and under investigation, then the closed ones.
func rank(state string) int {
	switch state {
	case vex.Affected:
		return 0
	case StateOpen, vex.UnderInvestigation:
		return 1
	}
	return 2
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := rank(a.State), rank(b.State); ra != rb {
			return ra < rb
		}
		if a.Exploited() != b.Exploited() {
			return a.Exploited()
		}
		if sa, sb := epssScore(a), epssScore(b); sa != sb {
			return sa > sb
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		return a.ID < b.ID
	})
}

func epssScore(f Finding) float64 {
	if f.EPSS == nil {
		return 0
	}
	return f.EPSS.Score
}

// Components returns the SBOM's components without file listings.
func Components(bom *cyclonedx.BOM) []cyclonedx.Component {
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

// Label is name@version.
func Label(c cyclonedx.Component) string {
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// hash keeps each snapshot source in its own cache folder.
func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}
