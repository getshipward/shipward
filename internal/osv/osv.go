// Package osv holds the part of the OSV schema (https://ossf.github.io/osv-schema/) that shipward needs, and decides whether
// a package version is affected. Version comparison comes from osv-scalibr's semantic package; the range walk follows
// osv-scalibr's enricher/vulnmatch/osvlocal (Apache-2.0, see NOTICE).
package osv

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/google/osv-scalibr/semantic"
)

// Vulnerability is an OSV record cut down to what matching and reporting need.
type Vulnerability struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Published string     `json:"published,omitempty"`
	Modified  string     `json:"modified,omitempty"`
	Withdrawn string     `json:"withdrawn,omitempty"`
	Severity  []Severity `json:"severity,omitempty"`
	Affected  []Affected `json:"affected,omitempty"`
	// URL is one advisory page for people to read (not part of OSV: picked from the references).
	URL string `json:"url,omitempty"`
	// Rating is the source's own rating (GitHub's LOW, MODERATE, HIGH, CRITICAL), when it gives one.
	Rating string `json:"rating,omitempty"`
}

// Severity is a scored severity, e.g. type CVSS_V3 with the vector as score.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected lists the affected versions of one package.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Package names a package in an ecosystem ("NuGet", "npm", ...).
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range is a list of version events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one point of a range. Exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Parse reads one full OSV record and cuts it down. Only affected entries of the given ecosystem are kept.
func Parse(data []byte, ecosystem string) (Vulnerability, error) {
	var full struct {
		Vulnerability
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
		DatabaseSpecific json.RawMessage `json:"database_specific"`
	}
	if err := json.Unmarshal(data, &full); err != nil {
		return Vulnerability{}, err
	}
	v := full.Vulnerability
	var kept []Affected
	for _, a := range v.Affected {
		if a.Package.Ecosystem == ecosystem {
			kept = append(kept, a)
		}
	}
	v.Affected = kept
	// The advisory page of the record itself (e.g. GitHub's for a GHSA record), not another database's.
	for _, r := range full.References {
		if r.Type == "ADVISORY" && strings.Contains(r.URL, v.ID) {
			v.URL = r.URL
			break
		}
	}
	if v.URL == "" {
		v.URL = "https://osv.dev/vulnerability/" + v.ID
	}
	var db struct {
		Severity string `json:"severity"`
	}
	if json.Unmarshal(full.DatabaseSpecific, &db) == nil {
		v.Rating = strings.ToUpper(db.Severity)
	}
	return v, nil
}

// CVEs returns the record's CVE IDs (its own ID or aliases).
func (v Vulnerability) CVEs() []string {
	var out []string
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

// Fixed returns the fixed versions the record names for a package, sorted.
func (v Vulnerability) Fixed(p Package) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range v.Affected {
		if !sameName(a.Package, p) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					out = append(out, e.Fixed)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Affects reports whether version of package p is affected.
func (v Vulnerability) Affects(p Package, version string) bool {
	if v.Withdrawn != "" {
		return false
	}
	for _, a := range v.Affected {
		if !sameName(a.Package, p) {
			continue
		}
		for _, x := range a.Versions {
			if x == version {
				return true
			}
		}
		for _, r := range a.Ranges {
			if rangeContains(r, p.Ecosystem, version) {
				return true
			}
		}
	}
	return false
}

func rangeContains(r Range, ecosystem, version string) bool {
	if (r.Type != "ECOSYSTEM" && r.Type != "SEMVER") || len(r.Events) == 0 {
		return false
	}
	vp, err := semantic.Parse(version, ecosystem)
	if err != nil {
		return false
	}
	cmp := func(other string) (int, bool) {
		c, err := vp.CompareStr(other)
		return c, err == nil
	}

	events := append([]Event(nil), r.Events...)
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if a.Introduced == "0" {
			return b.Introduced != "0"
		}
		if b.Introduced == "0" {
			return false
		}
		pa, err := semantic.Parse(eventVersion(a), ecosystem)
		if err != nil {
			return false
		}
		c, err := pa.CompareStr(eventVersion(b))
		return err == nil && c < 0
	})

	affected := false
	for _, e := range events {
		switch {
		case affected && e.Fixed != "":
			c, ok := cmp(e.Fixed)
			affected = ok && c < 0
		case affected && e.LastAffected != "":
			c, ok := cmp(e.LastAffected)
			affected = e.LastAffected == version || (ok && c <= 0)
		case affected && e.Limit != "":
			c, ok := cmp(e.Limit)
			affected = ok && c < 0
		case !affected && e.Introduced != "":
			c, ok := cmp(e.Introduced)
			affected = e.Introduced == "0" || (ok && c >= 0)
		}
	}
	return affected
}

func eventVersion(e Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.Limit != "":
		return e.Limit
	}
	return e.LastAffected
}

// Ecosystems are the OSV ecosystems shipward knows, by purl type.
var Ecosystems = map[string]string{
	packageurl.TypeNPM:      "npm",
	packageurl.TypeNuget:    "NuGet",
	packageurl.TypeComposer: "Packagist",
	packageurl.TypeGolang:   "Go",
	packageurl.TypePyPi:     "PyPI",
	packageurl.TypeMaven:    "Maven",
	packageurl.TypeCargo:    "crates.io",
	packageurl.TypeGem:      "RubyGems",
}

// EcosystemNames lists the ecosystems shipward matches, for people: the OSV name and, where it differs, the purl type.
func EcosystemNames() []string {
	var out []string
	for typ, eco := range Ecosystems {
		if strings.EqualFold(typ, eco) {
			out = append(out, eco)
		} else {
			out = append(out, eco+" ("+typ+")")
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

var pythonSeparators = regexp.MustCompile(`[-_.]+`)

// FromPURL returns the OSV package and version for a purl, or ok=false for a purl type shipward does not match.
func FromPURL(s string) (p Package, version string, ok bool) {
	purl, err := packageurl.FromString(s)
	if err != nil || purl.Version == "" {
		return Package{}, "", false
	}
	eco, known := Ecosystems[purl.Type]
	if !known {
		return Package{}, "", false
	}
	name, version := purl.Name, purl.Version
	switch eco {
	case "Maven":
		if purl.Namespace != "" {
			name = purl.Namespace + ":" + name
		}
	default:
		if purl.Namespace != "" {
			name = purl.Namespace + "/" + name
		}
	}
	switch eco {
	case "Go":
		if name == "stdlib" {
			version = strings.TrimPrefix(version, "go")
		}
		version = strings.TrimPrefix(version, "v")
	case "PyPI":
		name = pythonSeparators.ReplaceAllString(strings.ToLower(name), "-")
	}
	return Package{Ecosystem: eco, Name: name}, version, true
}

// Key is the lookup key of a package: names compared without case where the registry ignores case.
func Key(p Package) string {
	switch p.Ecosystem {
	case "NuGet", "Packagist":
		return p.Ecosystem + "/" + strings.ToLower(p.Name)
	case "PyPI":
		return p.Ecosystem + "/" + pythonSeparators.ReplaceAllString(strings.ToLower(p.Name), "-")
	}
	return p.Ecosystem + "/" + p.Name
}

func sameName(a, b Package) bool { return Key(a) == Key(b) }
