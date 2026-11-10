// Package scan matches an SBOM against the vulnerability snapshot and the maker's VEX decisions, on the maker's
// machine.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
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

// Exploited reports whether CISA or ENISA list the advisory as exploited somewhere. That alone does not make it an
// actively exploited vulnerability in the maker's product (CRA Art. 3(42), 14(1)): a person decides that.
func (f Finding) Exploited() bool { return f.KEV != "" || f.EUVD != "" }

// NeedsWork reports whether the finding has no final decision (open, under investigation, or affected).
func (f Finding) NeedsWork() bool { return !vex.Final(f.State) }

// IDs returns the advisory ID and its aliases.
func (f Finding) IDs() []string { return append([]string{f.ID}, f.Aliases...) }

// Names of the feeds in Report.Feeds.
const (
	FeedKEV  = "CISA KEV"
	FeedEUVD = "ENISA EUVD"
	FeedEPSS = "EPSS"
)

// StaleAfter is the age after which a scan warns that its data is old. The snapshot is made daily.
const StaleAfter = 48 * time.Hour

// Feed is the state of one exploitation feed in a scan.
type Feed struct {
	Name string `json:"name"`
	// Used is false when the feed could not be loaded: then nothing from it is in the findings.
	Used bool `json:"used"`
	// Date is when the copy used was made: for KEV the snapshot's date, for EUVD and EPSS when shipward fetched it.
	Date     time.Time `json:"date,omitzero"`
	AgeHours *float64  `json:"age_hours,omitempty"`
}

// Report is the result of one scan.
type Report struct {
	SBOM     string    `json:"sbom"`
	Snapshot time.Time `json:"snapshot"`
	// SnapshotAgeHours is the snapshot's age at scan time; SnapshotExpires is when its builder stops standing behind it.
	SnapshotAgeHours float64           `json:"snapshot_age_hours"`
	SnapshotExpires  time.Time         `json:"snapshot_expires,omitzero"`
	Feeds            []Feed            `json:"feeds"`
	Warnings         []string          `json:"warnings,omitempty"`
	Checked          int               `json:"checked"`
	NotChecked       []string          `json:"not_checked,omitempty"`
	Findings         []Finding         `json:"findings"`
	Unused           []vex.Statement   `json:"unused_decisions,omitempty"`
	Sources          []snapshot.Source `json:"sources"`
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
	Now       func() time.Time
}

type target struct {
	label, purl, version string
	pkg                  osv.Package
}

// Run scans the SBOM.
func Run(ctx context.Context, o Options) (*Report, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
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

	at := now()
	rep := &Report{SBOM: o.SBOM, Snapshot: data.Index.Created, SnapshotExpires: data.Index.Expires,
		SnapshotAgeHours: hours(at.Sub(data.Index.Created)), Checked: len(targets), NotChecked: notChecked,
		Findings: []Finding{}, Sources: data.Index.Sources}
	if data.Warning != "" {
		rep.Warnings = append(rep.Warnings, data.Warning)
	}
	if age := at.Sub(data.Index.Created); age > StaleAfter {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("the vulnerability snapshot is %s old (made %s): advisories published since then are missing",
			Age(age), data.Index.Created.UTC().Format("2006-01-02 15:04 MST")))
	}
	if !data.Index.Expires.IsZero() && at.After(data.Index.Expires) {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("the vulnerability snapshot expired on %s: no newer one could be loaded",
			data.Index.Expires.UTC().Format("2006-01-02 15:04 MST")))
	}
	kev := Feed{Name: FeedKEV, Used: data.Exploited.KEV != nil}
	if kev.Used {
		kev.Date, kev.AgeHours = data.Index.Created, ptr(hours(at.Sub(data.Index.Created)))
	} else {
		rep.Warnings = append(rep.Warnings, "the snapshot has no CISA KEV list: no advisory is marked as exploited by CISA")
	}
	rep.Feeds = append(rep.Feeds, kev)
	type match struct {
		t target
		v *osv.Vulnerability
	}
	var matches []match
	ids := map[string]bool{}
	for _, t := range targets {
		for _, v := range byPackage[osv.Key(t.pkg)] {
			if v.Affects(t.pkg, t.version) {
				matches = append(matches, match{t, v})
				for _, id := range append([]string{v.ID}, v.Aliases...) {
					ids[id] = true
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
		Now:      now,
		Offline:  o.Offline,
	}).Load(ctx, ids)
	rep.Warnings = append(rep.Warnings, live.Warnings...)
	data.Exploited.EUVD, data.Exploited.EPSS = live.EUVD, live.EPSS
	euvd := liveFeed(FeedEUVD, live.EUVD != nil, live.EUVDFetched, at)
	epss := liveFeed(FeedEPSS, live.EPSS != nil, live.EPSSFetched, at)
	rep.Feeds = append(rep.Feeds, euvd, epss)
	if euvd.Used {
		rep.Sources = append(rep.Sources, snapshot.EUVDSource)
	} else {
		rep.Warnings = append(rep.Warnings, "ENISA's list of exploited vulnerabilities (EUVD) could not be loaded: exploitation was checked against CISA KEV only")
	}
	if epss.Used {
		rep.Sources = append(rep.Sources, snapshot.EPSSSource)
	}
	for _, f := range []Feed{euvd, epss} {
		if f.Used && !f.Date.IsZero() && at.Sub(f.Date) > StaleAfter {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("the %s copy is %s old (fetched %s)", f.Name, Age(at.Sub(f.Date)),
				f.Date.UTC().Format("2006-01-02 15:04 MST")))
		}
	}

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
	// Every ID of the advisory, not only CVEs: ENISA also lists GHSA and its own EUVD IDs.
	for _, id := range f.IDs() {
		if k, ok := ex.KEV[id]; ok && f.KEV == "" {
			f.KEV = k.Added
		}
		if e, ok := ex.EUVD[id]; ok && f.EUVD == "" {
			f.EUVD = e.ID
		}
		if s, ok := ex.EPSS[id]; ok && (f.EPSS == nil || s.Score > f.EPSS.Score) {
			f.EPSS = &s
		}
	}
	return f
}

// MissingExploitedFeeds names the exploitation feeds (CISA KEV, ENISA EUVD) that this scan could not use.
func (r *Report) MissingExploitedFeeds() []string {
	var out []string
	for _, f := range r.Feeds {
		if !f.Used && (f.Name == FeedKEV || f.Name == FeedEUVD) {
			out = append(out, f.Name)
		}
	}
	return out
}

// OlderThan describes the data of this scan that is older than max: the snapshot and the feeds it used.
func (r *Report) OlderThan(max time.Duration, now time.Time) []string {
	var out []string
	if age := now.Sub(r.Snapshot); age > max {
		out = append(out, fmt.Sprintf("the snapshot is %s old", Age(age)))
	}
	for _, f := range r.Feeds {
		if f.Name == FeedKEV || !f.Used || f.Date.IsZero() {
			continue // KEV is part of the snapshot
		}
		if age := now.Sub(f.Date); age > max {
			out = append(out, fmt.Sprintf("the %s copy is %s old", f.Name, Age(age)))
		}
	}
	return out
}

func liveFeed(name string, used bool, fetched, now time.Time) Feed {
	f := Feed{Name: name, Used: used}
	if used && !fetched.IsZero() {
		f.Date, f.AgeHours = fetched.UTC(), ptr(hours(now.Sub(fetched)))
	}
	return f
}

// Age writes a duration for people: minutes, hours or days.
func Age(d time.Duration) string {
	d = max(d, 0) // a clock slightly behind the builder's
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// hours is a duration in hours, to one decimal.
func hours(d time.Duration) float64 { return math.Round(d.Hours()*10) / 10 }

func ptr[T any](v T) *T { return &v }

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
