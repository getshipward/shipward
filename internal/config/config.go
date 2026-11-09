// Package config reads cra.yaml, the per-product settings file that lives in the maker's repository.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// DefaultFile is the name cra looks for in the working directory.
const DefaultFile = "cra.yaml"

// Config is the content of cra.yaml.
type Config struct {
	Product      Product      `yaml:"product"`
	Manufacturer Manufacturer `yaml:"manufacturer"`
	SBOM         SBOM         `yaml:"sbom"`
	VEX          VEX          `yaml:"vex"`
	Security     Security     `yaml:"security"`
	Docs         Docs         `yaml:"docs"`
	Reports      Reports      `yaml:"reports"`

	// dir is the directory cra.yaml was read from; relative paths are resolved against it.
	dir string
}

// Product names the product the SBOM describes.
type Product struct {
	Name string `yaml:"name"`
	// Version is usually left empty and passed per release (cra sbom --version, or the CI tag).
	Version string `yaml:"version"`
	// Licence is the SPDX expression the product is distributed under, e.g. "LicenseRef-<maker>-proprietary".
	Licence string `yaml:"licence"`
	// Executable, Archive and Structured describe the delivered file (BSI TR-03183-2). Leave out what you do not know.
	Executable *bool `yaml:"executable"`
	Archive    *bool `yaml:"archive"`
	Structured *bool `yaml:"structured"`

	// For cra init's documents (CRA Annex II and VII). Leave out what you do not know: the drafts mark it TODO.
	// Description says what the product is, in one sentence; Purpose its intended purpose (who uses it, for what).
	Description string `yaml:"description"`
	Purpose     string `yaml:"purpose"`
	// Website is where users find the product and its documents.
	Website string `yaml:"website"`
	// SupportUntil is the end of the support period, as YYYY-MM (CRA Art. 13(8): at least five years, unless the
	// product is expected to be in use for less).
	SupportUntil string `yaml:"support_until"`
	// Markets are the Member States where the product is made available (ISO codes such as SI, DE), or "EU" for all
	// of them. Reports name them (CRA Art. 14(2)(a), 14(4)(a)).
	Markets []string `yaml:"markets"`
}

// Manufacturer is the supplier written into the SBOM metadata.
type Manufacturer struct {
	Name  string `yaml:"name"`
	URL   string `yaml:"url"`
	Email string `yaml:"email"`
	// Address is the postal address (CRA Annex II point 1, Annex V point 2).
	Address string `yaml:"address"`
}

// Security says how people report vulnerabilities (CRA Annex I part II, Annex II point 2).
type Security struct {
	// Contact is the single point of contact: a mailto: or https: URI. Default: mailto: and the manufacturer's email.
	Contact string `yaml:"contact"`
	// Policy is the URL where the coordinated vulnerability disclosure policy (SECURITY.md) is published.
	Policy string `yaml:"policy"`
	// Languages for reports, e.g. [en, sl]. Default [en].
	Languages []string `yaml:"languages"`
}

// Reports says where cra report keeps its cases and whom they go to.
type Reports struct {
	// Dir holds one folder per case. Default "cra/reports". The cases describe unfixed vulnerabilities: keep the
	// repository private.
	Dir string `yaml:"dir"`
	// CSIRT is the CSIRT coordinator of the Member State of the manufacturer's main establishment (CRA Art. 14(7)),
	// e.g. "SI-CERT". Reports go to it through ENISA's single reporting platform.
	CSIRT string `yaml:"csirt"`
}

// Docs says where cra init writes its drafts.
type Docs struct {
	// Dir is the folder for the CRA documents. Default "cra". SECURITY.md goes to the repository root.
	Dir string `yaml:"dir"`
}

// SBOM controls what is scanned and where the result goes.
type SBOM struct {
	// Path is the directory to scan, relative to cra.yaml. Default ".".
	Path string `yaml:"path"`
	// Exclude holds glob patterns (Syft syntax, e.g. "./tests/**") left out of the scan.
	Exclude []string `yaml:"exclude"`
	// Output is the file the SBOM is written to. Default "sbom/sbom.cdx.json".
	Output string `yaml:"output"`
	// Extra is a hand-kept list of components no package manager knows about (engines, vendored code, add-ons).
	// Default "components.extra.yaml"; a missing file is not an error.
	Extra string `yaml:"extra"`
	// Licences holds the licences a person confirmed (cra licences). Default "licences.yaml"; a missing file is not an
	// error.
	Licences string `yaml:"licences"`
}

// VEX says where the maker's decisions about advisories live.
type VEX struct {
	// Path is the decisions file (cra triage set writes it). Default "vex.yaml".
	Path string `yaml:"path"`
	// Output is the OpenVEX document cra triage export writes. Default "sbom/vex.openvex.json".
	Output string `yaml:"output"`
}

// Load reads and checks a cra.yaml file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.dir = filepath.Dir(path)
	c.setDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) setDefaults() {
	if c.SBOM.Path == "" {
		c.SBOM.Path = "."
	}
	if c.SBOM.Output == "" {
		c.SBOM.Output = "sbom/sbom.cdx.json"
	}
	if c.SBOM.Extra == "" {
		c.SBOM.Extra = "components.extra.yaml"
	}
	if c.Security.Contact == "" && c.Manufacturer.Email != "" {
		c.Security.Contact = "mailto:" + c.Manufacturer.Email
	}
	if len(c.Security.Languages) == 0 {
		c.Security.Languages = []string{"en"}
	}
	if c.Reports.Dir == "" {
		c.Reports.Dir = "cra/reports"
	}
	if c.Docs.Dir == "" {
		c.Docs.Dir = "cra"
	}
	if c.VEX.Path == "" {
		c.VEX.Path = "vex.yaml"
	}
	if c.VEX.Output == "" {
		c.VEX.Output = "sbom/vex.openvex.json"
	}
	if c.SBOM.Licences == "" {
		c.SBOM.Licences = "licences.yaml"
	}
	// CI workflows are build tooling, not part of the shipped product.
	c.SBOM.Exclude = append(c.SBOM.Exclude, "./.github/**")
}

func (c *Config) validate() error {
	var errs []error
	if c.Product.Name == "" {
		errs = append(errs, errors.New("product.name is required"))
	}
	if c.Manufacturer.Name == "" {
		errs = append(errs, errors.New("manufacturer.name is required"))
	}
	if c.Product.SupportUntil != "" {
		if _, err := time.Parse("2006-01", c.Product.SupportUntil); err != nil {
			errs = append(errs, fmt.Errorf("product.support_until %q is not YYYY-MM", c.Product.SupportUntil))
		}
	}
	if c.Security.Contact != "" && !strings.HasPrefix(c.Security.Contact, "mailto:") && !strings.HasPrefix(c.Security.Contact, "https://") {
		errs = append(errs, fmt.Errorf("security.contact %q must start with mailto: or https://", c.Security.Contact))
	}
	return errors.Join(errs...)
}

// Resolve turns a path from cra.yaml into one relative to the working directory.
func (c *Config) Resolve(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}
