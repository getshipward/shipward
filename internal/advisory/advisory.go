// Package advisory writes drafts of the advisory a manufacturer publishes about a fixed vulnerability once the security
// update is available (EU Cyber Resilience Act, Annex I Part II(4) and (8)): a Markdown page for people and, when asked,
// a CSAF 2.0 document (profile "Security advisory") for tools. A person completes and publishes them; shipward does not
// publish anything.
package advisory

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/*.tmpl
var templates embed.FS

// Advisory holds what the drafts say. Empty fields become TODOs in Markdown.
type Advisory struct {
	ID      string   // the advisory's main ID: a CVE, GHSA, EUVD or the maker's own
	Aliases []string // other IDs of the same vulnerability
	Title   string

	Product      string   // product name
	Manufacturer string   // manufacturer name
	Namespace    string   // the manufacturer's website (CSAF publisher namespace)
	Contact      string   // where users ask questions
	Affected     []string // product versions affected
	FixedIn      string   // the product version with the security update

	Component   string // the affected component (purl), when the flaw is in a dependency
	Description string // what the vulnerability is
	Impact      string // what an attacker can do
	Severity    string // e.g. "high", or a CVSS rating
	CVSS        string // a CVSS vector, when known
	Remediation string // what users should do; default: update to FixedIn
	References  []string

	Date time.Time // when the draft was written
	Tool string    // "shipward 1.2.3", for the disclaimer
}

// Note is the disclaimer every draft carries.
func (a Advisory) Note() string {
	return fmt.Sprintf("Draft written by %s. It lists what CRA Annex I Part II(4) asks an advisory about a fixed "+
		"vulnerability to contain and helps you prepare; it is not legal advice. Complete it and check every line "+
		"before you publish it.", a.Tool)
}

// RemediationText is the remediation, or "update to <FixedIn>", or "".
func (a Advisory) RemediationText() string {
	switch {
	case a.Remediation != "":
		return a.Remediation
	case a.FixedIn != "":
		return fmt.Sprintf("Update %s to version %s or later.", a.Product, a.FixedIn)
	}
	return ""
}

// Markdown renders the advisory for people.
func Markdown(a Advisory) ([]byte, error) {
	funcs := template.FuncMap{"join": strings.Join}
	tmpl, err := template.New("advisory.md.tmpl").Funcs(funcs).Option("missingkey=error").ParseFS(templates, "templates/advisory.md.tmpl")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, a); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// CSAF renders the advisory as a CSAF 2.0 document, profile "Security advisory"
// (https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html). The document has tracking status "draft" and
// version "0": raise both when you publish it. It needs the affected versions, the fixed version and the manufacturer's
// website.
func CSAF(a Advisory) ([]byte, error) {
	var errs []error
	if len(a.Affected) == 0 {
		errs = append(errs, errors.New("CSAF needs the affected versions (--affected)"))
	}
	if a.FixedIn == "" {
		errs = append(errs, errors.New("CSAF needs the version with the fix (--fixed-in)"))
	}
	if !strings.HasPrefix(a.Namespace, "https://") && !strings.HasPrefix(a.Namespace, "http://") {
		errs = append(errs, errors.New("CSAF needs the manufacturer's website (manufacturer.url in shipward.yaml)"))
	}
	if a.Manufacturer == "" || a.Product == "" {
		errs = append(errs, errors.New("CSAF needs manufacturer.name and product.name"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	date := a.Date.UTC().Format(time.RFC3339)
	productID := func(v string) string { return "CSAFPID-" + slug(a.Product) + "-" + slug(v) }

	var versions []any
	var affectedIDs []string
	for _, v := range a.Affected {
		versions = append(versions, branch("product_version", v, productID(v), a.Product+" "+v))
		affectedIDs = append(affectedIDs, productID(v))
	}
	fixedID := productID(a.FixedIn)
	versions = append(versions, branch("product_version", a.FixedIn, fixedID, a.Product+" "+a.FixedIn))

	title := a.Title
	if title == "" {
		title = a.ID + " in " + a.Product
	}
	description := a.Description
	if description == "" {
		description = "TODO: what the vulnerability is."
	}
	vuln := map[string]any{
		"title": title,
		"notes": []any{map[string]any{"category": "description", "title": "Description", "text": description}},
		"product_status": map[string]any{
			"known_affected": affectedIDs,
			"fixed":          []string{fixedID},
		},
		"remediations": []any{map[string]any{
			"category":    "vendor_fix",
			"details":     a.RemediationText(),
			"product_ids": affectedIDs,
		}},
	}
	var ids []any
	for _, id := range append([]string{a.ID}, a.Aliases...) {
		if cveID.MatchString(id) {
			if _, ok := vuln["cve"]; !ok {
				vuln["cve"] = id
				continue
			}
		}
		ids = append(ids, map[string]any{"system_name": system(id), "text": id})
	}
	if len(ids) > 0 {
		vuln["ids"] = ids
	}
	if a.Impact != "" {
		vuln["threats"] = []any{map[string]any{"category": "impact", "details": a.Impact, "product_ids": affectedIDs}}
	}
	var refs []any
	for _, r := range a.References {
		refs = append(refs, map[string]any{"category": "external", "summary": "More information", "url": r})
	}
	if len(refs) > 0 {
		vuln["references"] = refs
	}

	docRefs := []any{map[string]any{"category": "external", "summary": a.Manufacturer, "url": a.Namespace}}
	document := map[string]any{
		"category":     "csaf_security_advisory",
		"csaf_version": "2.0",
		"lang":         "en",
		"title":        title,
		"publisher":    map[string]any{"category": "vendor", "name": a.Manufacturer, "namespace": a.Namespace},
		"notes": []any{
			map[string]any{"category": "summary", "title": "Summary", "text": summary(a, title)},
			map[string]any{"category": "legal_disclaimer", "title": "Draft", "text": a.Note()},
		},
		"references": docRefs,
		"tracking": map[string]any{
			"id":                   a.ID,
			"status":               "draft",
			"version":              "0",
			"initial_release_date": date,
			"current_release_date": date,
			"revision_history":     []any{map[string]any{"date": date, "number": "0", "summary": "Draft."}},
			"generator":            map[string]any{"date": date, "engine": map[string]any{"name": "shipward", "version": strings.TrimPrefix(a.Tool, "shipward ")}},
		},
	}
	if a.Severity != "" {
		document["aggregate_severity"] = map[string]any{"text": a.Severity}
	}
	doc := map[string]any{
		"document": document,
		"product_tree": map[string]any{"branches": []any{map[string]any{
			"category": "vendor", "name": a.Manufacturer,
			"branches": []any{map[string]any{"category": "product_name", "name": a.Product, "branches": versions}},
		}}},
		"vulnerabilities": []any{vuln},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func branch(category, name, id, full string) map[string]any {
	return map[string]any{"category": category, "name": name, "product": map[string]any{"product_id": id, "name": full}}
}

func summary(a Advisory, title string) string {
	s := title + ". "
	if len(a.Affected) > 0 {
		s += fmt.Sprintf("Affected: %s %s. ", a.Product, strings.Join(a.Affected, ", "))
	}
	if a.FixedIn != "" {
		s += fmt.Sprintf("Fixed in %s %s.", a.Product, a.FixedIn)
	}
	return strings.TrimSpace(s)
}

// system names the scheme of an advisory ID for CSAF's ids.
func system(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GitHub Security Advisory"
	case strings.HasPrefix(id, "EUVD-"):
		return "EUVD"
	}
	if i := strings.IndexAny(id, "-:"); i > 0 {
		return id[:i]
	}
	return "manufacturer"
}

var nonSlug = regexp.MustCompile(`[^A-Za-z0-9.]+`)

func slug(s string) string { return strings.Trim(nonSlug.ReplaceAllString(s, "-"), "-.") }

// FileName returns the base name for an advisory's files: its ID, safe for a file name.
func FileName(id string) string {
	if s := slug(id); s != "" {
		return s
	}
	return "advisory"
}
