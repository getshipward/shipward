// Package check measures an SBOM against a published guideline and says which fields are missing where. It reports
// facts about the file; it does not certify anything.
package check

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/github/go-spdx/v2/spdxexp"
)

// Level says how strongly the guideline asks for a field.
type Level string

const (
	// Must fields are required in every SBOM.
	Must Level = "MUST"
	// MustIfExists fields are required only when the information exists, so a gap is reported but does not fail.
	MustIfExists Level = "IF EXISTS"
)

// Result is one rule applied to the whole SBOM or to every component.
type Result struct {
	ID    string
	Level Level
	Title string
	// Total is the number of items the rule applies to (1 for SBOM-level rules); Passed how many meet it.
	Total, Passed int
	// Failing names the items that miss the rule (component name@version, or a reason for SBOM-level rules).
	Failing []string
}

// OK reports whether every item meets the rule.
func (r Result) OK() bool { return r.Passed == r.Total }

// BSIProfile is the guideline version the BSI rules below follow, and BSIDate the date of that version (from its
// document history).
const (
	BSIProfile = "BSI TR-03183-2 v2.1.0"
	BSIDate    = "2025-08-20"
)

// BSINewer reminds the reader that BSI may have published a newer version since.
const BSINewer = "BSI may have published a newer version of TR-03183-2 since: check bsi.bund.de before you rely on this list."

// BSI property names (TR-03183-2 v2.1.0, section 8.2) and their allowed values.
var bsiProperties = []struct {
	id, name, title string
	values          []string
}{
	{"bsi.component.filename", "bsi:component:filename", "Component filename (property bsi:component:filename)", nil},
	{"bsi.component.executable", "bsi:component:executable", "Executable property", []string{"executable", "non-executable"}},
	{"bsi.component.archive", "bsi:component:archive", "Archive property", []string{"archive", "no archive"}},
	{"bsi.component.structured", "bsi:component:structured", "Structured property", []string{"structured", "unstructured"}},
}

// BSI applies the data-field rules of BSI TR-03183-2 v2.1.0 (sections 4 and 5.2, CycloneDX mapping in 8.2) to a
// CycloneDX SBOM. Nested components (a component's own components) are checked too. Components of type "file" (file
// listings, not deliverable parts) are not checked.
func BSI(bom *cyclonedx.BOM) []Result {
	var comps []cyclonedx.Component
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		comps = flatten(comps, []cyclonedx.Component{*bom.Metadata.Component})
	}
	if bom.Components != nil {
		comps = flatten(comps, *bom.Components)
	}

	results := []Result{
		sbomRule("bsi.format", Must, "Format CycloneDX 1.6 or higher", formatProblem(bom)),
		sbomRule("bsi.sbom.creator", Must, "SBOM creator: email or URL (metadata.manufacturer)", creatorProblem(metadataManufacturer(bom))),
		sbomRule("bsi.sbom.timestamp", Must, "Timestamp", timestampProblem(bom)),
		sbomRule("bsi.sbom.no-vulnerabilities", Must, "No vulnerability information in the SBOM (vulnerabilities)", vulnerabilitiesProblem(bom)),
	}

	deps := dependencyRefs(bom)
	covered := compositionRefs(bom)
	componentRules := []componentRule{
		{"bsi.component.creator", "Component creator: email or URL (manufacturer)", Must,
			func(c cyclonedx.Component) bool { return creatorProblem(c.Manufacturer) == "" }},
		{"bsi.component.name", "Component name", Must,
			func(c cyclonedx.Component) bool { return strings.TrimSpace(c.Name) != "" }},
		{"bsi.component.version", "Component version", Must,
			func(c cyclonedx.Component) bool { return strings.TrimSpace(c.Version) != "" }},
		{"bsi.component.dependencies", "Dependencies listed (entry in dependencies, empty allowed)", Must,
			func(c cyclonedx.Component) bool { return deps[c.BOMRef] }},
		{"bsi.component.completeness", "Completeness of dependencies stated (compositions)", Must,
			func(c cyclonedx.Component) bool { return covered[c.BOMRef] }},
		{"bsi.component.licence", "Distribution licence (SPDX, acknowledgement \"concluded\")", Must,
			func(c cyclonedx.Component) bool { return hasLicence(c, cyclonedx.LicenseAcknowledgementConcluded) }},
		{"bsi.component.hash", "SHA-512 of the deployable component (distribution reference)", Must, hasSHA512},
	}
	for _, p := range bsiProperties {
		componentRules = append(componentRules, componentRule{p.id, p.title, Must,
			func(c cyclonedx.Component) bool { return hasProperty(c, p.name, p.values) }})
	}
	componentRules = append(componentRules, []componentRule{
		{"bsi.component.identifier", "Other unique identifier (purl, CPE or SWID)", MustIfExists,
			func(c cyclonedx.Component) bool { return c.PackageURL != "" || c.CPE != "" || c.SWID != nil }},
		{"bsi.component.source-uri", "Source code URI (source-distribution reference)", MustIfExists,
			func(c cyclonedx.Component) bool { return hasExternalRef(c, cyclonedx.ERTypeSourceDistribution) }},
		{"bsi.component.distribution-uri", "URI of the deployable form (distribution reference)", MustIfExists,
			func(c cyclonedx.Component) bool { return hasExternalRef(c, cyclonedx.ERTypeDistribution) }},
		{"bsi.component.original-licence", "Original licence (acknowledgement \"declared\")", MustIfExists,
			func(c cyclonedx.Component) bool { return hasLicence(c, cyclonedx.LicenseAcknowledgementDeclared) }},
	}...)

	for _, rule := range componentRules {
		r := Result{ID: rule.id, Level: rule.level, Title: rule.title, Total: len(comps)}
		for _, c := range comps {
			if rule.ok(c) {
				r.Passed++
			} else {
				r.Failing = append(r.Failing, label(c))
			}
		}
		results = append(results, r)
	}

	results = append(results, sbomRule("bsi.sbom.uri", MustIfExists, "SBOM URI (serialNumber)", func() string {
		if bom.SerialNumber == "" {
			return "no serialNumber"
		}
		return ""
	}()))
	return results
}

// flatten appends the components and, depth first, their nested components, without file listings.
func flatten(out, list []cyclonedx.Component) []cyclonedx.Component {
	for _, c := range list {
		if c.Type == cyclonedx.ComponentTypeFile {
			continue
		}
		nested := c.Components
		c.Components = nil
		out = append(out, c)
		if nested != nil {
			out = flatten(out, *nested)
		}
	}
	return out
}

// vulnerabilitiesProblem: TR-03183-2 keeps vulnerability information out of the SBOM (it changes daily; it belongs in
// a separate document such as VEX).
func vulnerabilitiesProblem(bom *cyclonedx.BOM) string {
	if bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) > 0 {
		return fmt.Sprintf("the SBOM has %d vulnerabilities entries: keep them in a separate document (VEX)", len(*bom.Vulnerabilities))
	}
	return ""
}

type componentRule struct {
	id, title string
	level     Level
	ok        func(cyclonedx.Component) bool
}

func sbomRule(id string, level Level, title, problem string) Result {
	r := Result{ID: id, Level: level, Title: title, Total: 1}
	if problem == "" {
		r.Passed = 1
	} else {
		r.Failing = []string{problem}
	}
	return r
}

func formatProblem(bom *cyclonedx.BOM) string {
	if bom.SpecVersion < cyclonedx.SpecVersion1_6 {
		return fmt.Sprintf("specVersion %s is below 1.6", bom.SpecVersion)
	}
	return ""
}

func metadataManufacturer(bom *cyclonedx.BOM) *cyclonedx.OrganizationalEntity {
	if bom.Metadata == nil {
		return nil
	}
	return bom.Metadata.Manufacturer
}

func creatorProblem(e *cyclonedx.OrganizationalEntity) string {
	if e == nil {
		return "no manufacturer"
	}
	if e.Contact != nil {
		for _, c := range *e.Contact {
			if c.Email != "" {
				return ""
			}
		}
	}
	if e.URL != nil {
		for _, u := range *e.URL {
			if u != "" {
				return ""
			}
		}
	}
	return "manufacturer has no email and no URL"
}

func timestampProblem(bom *cyclonedx.BOM) string {
	if bom.Metadata == nil || bom.Metadata.Timestamp == "" {
		return "no metadata.timestamp"
	}
	if _, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err != nil {
		return fmt.Sprintf("timestamp %q is not RFC 3339", bom.Metadata.Timestamp)
	}
	return ""
}

func dependencyRefs(bom *cyclonedx.BOM) map[string]bool {
	refs := map[string]bool{}
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			refs[d.Ref] = true
		}
	}
	return refs
}

func compositionRefs(bom *cyclonedx.BOM) map[string]bool {
	refs := map[string]bool{}
	if bom.Compositions == nil {
		return refs
	}
	for _, c := range *bom.Compositions {
		if c.Aggregate == "" || c.Aggregate == cyclonedx.CompositionAggregateNotSpecified {
			continue
		}
		for _, list := range []*[]cyclonedx.BOMReference{c.Dependencies, c.Assemblies} {
			if list == nil {
				continue
			}
			for _, r := range *list {
				refs[string(r)] = true
			}
		}
	}
	return refs
}

func hasLicence(c cyclonedx.Component, ack cyclonedx.LicenseAcknowledgement) bool {
	if c.Licenses == nil {
		return false
	}
	for _, l := range *c.Licenses {
		switch {
		case l.Expression != "" && l.Acknowledgement != nil && *l.Acknowledgement == ack && validSPDX(l.Expression):
			return true
		case l.License != nil && l.License.ID != "" && l.License.Acknowledgement == ack && validSPDX(l.License.ID):
			return true
		}
	}
	return false
}

// validSPDX reports whether s is an SPDX licence expression (TR-03183-2 asks for SPDX identifiers; LicenseRef-... is
// SPDX's way to name any other licence).
func validSPDX(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	ok, _ := spdxexp.ValidateLicenses([]string{s})
	return ok
}

func hasSHA512(c cyclonedx.Component) bool {
	if c.ExternalReferences == nil {
		return false
	}
	for _, ref := range *c.ExternalReferences {
		if ref.Type != cyclonedx.ERTypeDistribution || ref.Hashes == nil {
			continue
		}
		for _, h := range *ref.Hashes {
			if h.Algorithm == cyclonedx.HashAlgoSHA512 && validSHA512(h.Value) {
				return true
			}
		}
	}
	return false
}

// validSHA512 reports whether s is a SHA-512 in hex: 128 hex digits.
func validSHA512(s string) bool {
	if len(s) != 128 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func hasExternalRef(c cyclonedx.Component, typ cyclonedx.ExternalReferenceType) bool {
	if c.ExternalReferences == nil {
		return false
	}
	for _, ref := range *c.ExternalReferences {
		if ref.Type == typ && ref.URL != "" {
			return true
		}
	}
	return false
}

func hasProperty(c cyclonedx.Component, name string, allowed []string) bool {
	if c.Properties == nil {
		return false
	}
	for _, p := range *c.Properties {
		if p.Name != name || p.Value == "" {
			continue
		}
		if allowed == nil {
			return true
		}
		for _, v := range allowed {
			if p.Value == v {
				return true
			}
		}
	}
	return false
}

func label(c cyclonedx.Component) string {
	name := c.Name
	if name == "" {
		name = c.BOMRef
	}
	if c.Version != "" {
		return name + "@" + c.Version
	}
	return name
}
