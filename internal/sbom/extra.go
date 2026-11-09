package sbom

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"go.yaml.in/yaml/v3"
)

// ExtraComponent is one entry of components.extra.yaml: a part of the product that no package manager lists, such as
// the Godot engine, a Godot add-on copied into the project, or vendored C code.
type ExtraComponent struct {
	Name     string            `yaml:"name"`
	Version  string            `yaml:"version"`
	Type     string            `yaml:"type"` // CycloneDX component type; default "library"
	PURL     string            `yaml:"purl"`
	CPE      string            `yaml:"cpe"`
	Supplier string            `yaml:"supplier"`
	URL      string            `yaml:"url"`
	Licenses []string          `yaml:"licenses"` // SPDX IDs or expressions, e.g. "MIT"; several mean all apply
	Hashes   map[string]string `yaml:"hashes"`   // algorithm -> hex, e.g. sha256: ...

	// BSI TR-03183-2 fields. Fill only what you know.
	Creator  string `yaml:"creator"`  // email or URL of who made it (e.g. the project's web page)
	Source   string `yaml:"source"`   // URL of the source code (best: the tag or commit you used)
	Download string `yaml:"download"` // URL of the file you used; hashes.sha512 is the hash of that file
	Filename string `yaml:"filename"` // name of that file
	Form     Form   `yaml:",inline"`  // executable, archive, structured: true or false
}

type extraFile struct {
	Components []ExtraComponent `yaml:"components"`
}

var componentTypes = map[string]cyclonedx.ComponentType{
	"application": cyclonedx.ComponentTypeApplication,
	"framework":   cyclonedx.ComponentTypeFramework,
	"library":     cyclonedx.ComponentTypeLibrary,
	"firmware":    cyclonedx.ComponentTypeFirmware,
	"file":        cyclonedx.ComponentTypeFile,
	"platform":    cyclonedx.ComponentTypePlatform,
}

var hashAlgorithms = map[string]cyclonedx.HashAlgorithm{
	"sha256":   cyclonedx.HashAlgoSHA256,
	"sha384":   cyclonedx.HashAlgoSHA384,
	"sha512":   cyclonedx.HashAlgoSHA512,
	"sha3-256": cyclonedx.HashAlgoSHA3_256,
	"sha3-512": cyclonedx.HashAlgoSHA3_512,
}

// LoadExtra reads components.extra.yaml. A missing file returns no components and no error.
func LoadExtra(path string) ([]ExtraComponent, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f extraFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	for i, c := range f.Components {
		if err := c.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: components[%d]: %w", path, i, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return f.Components, nil
}

func (c ExtraComponent) validate() error {
	var errs []error
	if c.Name == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if c.Version == "" {
		errs = append(errs, errors.New("version is required"))
	}
	if c.Type != "" {
		if _, ok := componentTypes[c.Type]; !ok {
			errs = append(errs, fmt.Errorf("unknown type %q", c.Type))
		}
	}
	if c.Creator != "" && !validURL(c.Creator) && !strings.Contains(c.Creator, "@") {
		errs = append(errs, fmt.Errorf("creator %q is neither an email nor an http(s) URL", c.Creator))
	}
	for field, u := range map[string]string{"source": c.Source, "download": c.Download} {
		if u != "" && !validURL(u) {
			errs = append(errs, fmt.Errorf("%s %q is not an http(s) URL", field, u))
		}
	}
	for alg := range c.Hashes {
		if _, ok := hashAlgorithms[alg]; !ok {
			errs = append(errs, fmt.Errorf("unknown hash algorithm %q", alg))
		}
	}
	return errors.Join(errs...)
}

func (c ExtraComponent) toCycloneDX() cyclonedx.Component {
	typ := cyclonedx.ComponentTypeLibrary
	if c.Type != "" {
		typ = componentTypes[c.Type]
	}
	ref := c.PURL
	if ref == "" {
		ref = "extra:" + c.Name + "@" + c.Version
	}
	out := cyclonedx.Component{
		BOMRef:     ref,
		Type:       typ,
		Name:       c.Name,
		Version:    c.Version,
		PackageURL: c.PURL,
		CPE:        c.CPE,
	}
	if c.Supplier != "" || c.URL != "" {
		out.Supplier = &cyclonedx.OrganizationalEntity{Name: c.Supplier}
		if c.URL != "" {
			out.Supplier.URL = &[]string{c.URL}
		}
	}
	if len(c.Licenses) > 0 {
		out.Licenses = extraLicences(c.Licenses)
	}
	switch {
	case strings.Contains(c.Creator, "@") && !validURL(c.Creator):
		out.Manufacturer = &cyclonedx.OrganizationalEntity{Name: c.Supplier, Contact: &[]cyclonedx.OrganizationalContact{{Email: c.Creator}}}
	case c.Creator != "":
		out.Manufacturer = &cyclonedx.OrganizationalEntity{Name: c.Supplier, URL: &[]string{c.Creator}}
	}
	if c.Source != "" {
		out.ExternalReferences = &[]cyclonedx.ExternalReference{{Type: cyclonedx.ERTypeSourceDistribution, URL: c.Source}}
	}
	setForm(&out, c.Form)
	if len(c.Hashes) > 0 {
		hashes := make([]cyclonedx.Hash, 0, len(c.Hashes))
		for alg, v := range c.Hashes {
			hashes = append(hashes, cyclonedx.Hash{Algorithm: hashAlgorithms[alg], Value: v})
		}
		sort.Slice(hashes, func(i, j int) bool { return hashes[i].Algorithm < hashes[j].Algorithm })
		out.Hashes = &hashes
	}
	if c.Download != "" || c.Filename != "" {
		addDeployable(&out, c.Download, c.Filename, c.Hashes["sha512"])
	}
	return out
}

// extraLicences writes plain SPDX IDs as licence objects. CycloneDX 1.6 takes exactly one expression, so anything else
// becomes one "A AND B" expression.
func extraLicences(licences []string) *cyclonedx.Licenses {
	var objects cyclonedx.Licenses
	for _, l := range licences {
		choice := licenceChoice(l, cyclonedx.LicenseAcknowledgementDeclared)
		if choice.License == nil {
			objects = nil
			break
		}
		objects = append(objects, choice)
	}
	if objects != nil {
		return &objects
	}
	parts := make([]string, len(licences))
	for i, l := range licences {
		parts[i] = l
		if len(licences) > 1 && strings.ContainsAny(l, " ()") {
			parts[i] = "(" + l + ")"
		}
	}
	return &cyclonedx.Licenses{licenceChoice(strings.Join(parts, " AND "), cyclonedx.LicenseAcknowledgementDeclared)}
}
