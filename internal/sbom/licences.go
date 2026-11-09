package sbom

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/anchore/packageurl-go"
	"github.com/github/go-spdx/v2/spdxexp"
	"go.yaml.in/yaml/v3"
)

// LicenceConfirmation is one entry of licences.yaml: a licence a person checked for a component. cra sbom writes it
// as the "concluded" licence, which TR-03183-2 maps its "distribution licence" to.
type LicenceConfirmation struct {
	// Component is a purl ("pkg:nuget/MessagePack@3.1.12", or without "@version" for every version), or name@version
	// (or name) for a component without a purl.
	Component string `yaml:"component"`
	// Declared is the declared licence the person saw. An entry without a version applies only while the declared
	// licence stays the same, so a licence change in a new version needs a new check.
	Declared  string `yaml:"declared,omitempty"`
	Concluded string `yaml:"concluded"`
}

// LoadLicences reads licences.yaml. A missing file returns no entries and no error.
func LoadLicences(path string) ([]LicenceConfirmation, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []LicenceConfirmation
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	for i, e := range entries {
		switch {
		case e.Component == "":
			errs = append(errs, fmt.Errorf("%s: entry %d: component is required", path, i))
		case e.Concluded == "":
			errs = append(errs, fmt.Errorf("%s: %s: concluded is required", path, e.Component))
		case !hasVersion(e.Component) && e.Declared == "":
			errs = append(errs, fmt.Errorf("%s: %s: an entry for every version needs the declared licence it was checked against", path, e.Component))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return entries, nil
}

func hasVersion(key string) bool {
	if purl, err := packageurl.FromString(key); err == nil {
		return purl.Version != ""
	}
	return strings.Contains(key, "@")
}

// ComponentKeys returns the licences.yaml keys of a component: the one for this version, and the one for every version.
func ComponentKeys(c cyclonedx.Component) (exact, any string) {
	if purl, err := packageurl.FromString(c.PackageURL); err == nil {
		purl.Qualifiers, purl.Subpath = nil, ""
		exact = purl.ToString()
		purl.Version = ""
		return exact, purl.ToString()
	}
	if c.Version == "" {
		return c.Name, c.Name
	}
	return c.Name + "@" + c.Version, c.Name
}

// DeclaredLicence returns the component's declared licences as one string ("A AND B" when there are several), or "".
func DeclaredLicence(c cyclonedx.Component) string {
	if c.Licenses == nil {
		return ""
	}
	var parts []string
	for _, l := range *c.Licenses {
		switch {
		case l.Expression != "" && l.Acknowledgement != nil && *l.Acknowledgement == cyclonedx.LicenseAcknowledgementDeclared:
			parts = append(parts, l.Expression)
		case l.License != nil && l.License.Acknowledgement == cyclonedx.LicenseAcknowledgementDeclared:
			if id := l.License.ID; id != "" {
				parts = append(parts, id)
			} else if l.License.Name != "" {
				parts = append(parts, l.License.Name)
			}
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	sort.Strings(parts)
	for i, p := range parts {
		if strings.ContainsAny(p, " ()") {
			parts[i] = "(" + p + ")"
		}
	}
	return strings.Join(parts, " AND ")
}

// HasConcluded reports whether the component has a concluded licence.
func HasConcluded(c cyclonedx.Component) bool {
	if c.Licenses == nil {
		return false
	}
	for _, l := range *c.Licenses {
		if l.Expression != "" && l.Acknowledgement != nil && *l.Acknowledgement == cyclonedx.LicenseAcknowledgementConcluded {
			return true
		}
		if l.License != nil && l.License.Acknowledgement == cyclonedx.LicenseAcknowledgementConcluded {
			return true
		}
	}
	return false
}

// applyLicences writes the confirmed licences into the SBOM. An entry for this exact version wins over one for every
// version; the latter applies only when its declared licence matches.
func applyLicences(bom *cyclonedx.BOM, entries []LicenceConfirmation) {
	if bom.Components == nil || len(entries) == 0 {
		return
	}
	byKey := make(map[string]LicenceConfirmation, len(entries))
	for _, e := range entries {
		byKey[e.Component] = e
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.Type == cyclonedx.ComponentTypeFile || HasConcluded(*c) {
			continue
		}
		exact, any := ComponentKeys(*c)
		e, ok := byKey[exact]
		if !ok {
			e, ok = byKey[any]
			ok = ok && e.Declared == DeclaredLicence(*c)
		}
		if ok {
			setConcluded(c, e.Concluded)
		}
	}
}

// setConcluded adds a concluded licence. CycloneDX 1.6 allows either a list of licence objects or exactly one
// expression. A plain SPDX ID goes in as another licence object, so the declared licences stay; a compound expression
// replaces the list, because it is the field TR-03183-2 requires.
func setConcluded(c *cyclonedx.Component, expr string) {
	choice := licenceChoice(expr, cyclonedx.LicenseAcknowledgementConcluded)
	if choice.License == nil || c.Licenses == nil {
		c.Licenses = &cyclonedx.Licenses{choice}
		return
	}
	var list cyclonedx.Licenses
	for _, l := range *c.Licenses {
		if l.License == nil {
			// A single declared expression can stay only if it is a plain ID that converts to an object.
			ack := cyclonedx.LicenseAcknowledgementDeclared
			if l.Acknowledgement != nil {
				ack = *l.Acknowledgement
			}
			if l = licenceChoice(l.Expression, ack); l.License == nil {
				c.Licenses = &cyclonedx.Licenses{choice}
				return
			}
		}
		list = append(list, l)
	}
	list = append(list, choice)
	c.Licenses = &list
}

// licenceChoice writes a plain SPDX licence ID as a licence object and anything else as an expression. Only objects
// can be combined in one list (CycloneDX 1.6).
func licenceChoice(expr string, ack cyclonedx.LicenseAcknowledgement) cyclonedx.LicenseChoice {
	expr = strings.TrimSpace(expr)
	if isPlainSPDXID(expr) {
		return cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: expr, Acknowledgement: ack}}
	}
	return cyclonedx.LicenseChoice{Expression: expr, Acknowledgement: &ack}
}

// isPlainSPDXID reports whether s is one ID from the SPDX licence list (not an expression, not a LicenseRef).
func isPlainSPDXID(s string) bool {
	if s == "" || strings.ContainsAny(s, " ()+") || strings.HasPrefix(s, "LicenseRef-") || strings.HasPrefix(s, "DocumentRef-") {
		return false
	}
	ok, _ := spdxexp.ValidateLicenses([]string{s})
	return ok
}
