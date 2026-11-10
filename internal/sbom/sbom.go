// Package sbom makes a CycloneDX 1.6 SBOM of a product: Syft catalogs the source tree, and components.extra.yaml
// adds what no package manager lists. Everything runs locally; nothing is sent anywhere.
//
// It is a source SBOM: the components come from lock files and manifests before the build (CycloneDX lifecycle
// "pre-build"), not from the built product.
package sbom

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/source"

	// Syft's RPM cataloger refuses to run without a registered sqlite driver.
	_ "modernc.org/sqlite"
)

// Lifecycle is the CycloneDX lifecycle phase of the SBOMs shipward makes: "pre-build", because the components come
// from lock files and manifests, not from the built product.
const Lifecycle = cyclonedx.LifecyclePhasePreBuild

// Options describe one SBOM run.
type Options struct {
	Path         string // directory to scan
	Exclude      []string
	Product      string
	Version      string
	Manufacturer Supplier
	Extra        []ExtraComponent
	Licences     []LicenceConfirmation
	ToolVersion  string // version of shipward, recorded in the SBOM metadata

	// ProductLicence is the SPDX expression the product is distributed under; it is the maker's own statement, so it
	// is written as concluded.
	ProductLicence string
	ProductForm    Form
	// Artifact is the delivered file of this release (hashed for the SBOM), ArtifactURL where it can be downloaded.
	Artifact    string
	ArtifactURL string
	// NuGetCache is the NuGet global packages folder; empty skips reading it.
	NuGetCache string
}

// Supplier is the manufacturer named in the SBOM.
type Supplier struct {
	Name  string
	URL   string
	Email string
}

// Generate scans Options.Path and returns the SBOM.
func Generate(ctx context.Context, o Options) (*cyclonedx.BOM, error) {
	if o.ProductLicence != "" && !ValidLicence(o.ProductLicence) {
		return nil, fmt.Errorf("product.licence %q is not an SPDX licence expression: use an SPDX ID (MIT), an expression (MIT OR Apache-2.0) or LicenseRef-<you>-proprietary", o.ProductLicence)
	}
	srcCfg := syft.DefaultGetSourceConfig().
		WithSources("dir").
		WithExcludeConfig(source.ExcludeConfig{Paths: o.Exclude})
	src, err := syft.GetSource(ctx, o.Path, srcCfg)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", o.Path, err)
	}
	defer src.Close()

	// Development dependencies are not part of the delivered product. Syft leaves npm's out only when told so (its
	// default today), so say it here rather than rely on the default; Composer's packages-dev are never catalogued.
	pkgCfg := pkgcataloging.DefaultConfig()
	pkgCfg = pkgCfg.WithJavascriptConfig(pkgCfg.JavaScript.WithIncludeDevDependencies(false))
	sbomCfg := syft.DefaultCreateSBOMConfig().WithTool("shipward", o.ToolVersion).WithPackagesConfig(pkgCfg)
	s, err := syft.CreateSBOM(ctx, src, sbomCfg)
	if err != nil {
		return nil, fmt.Errorf("catalog %s: %w", o.Path, err)
	}

	bom := cyclonedxhelpers.ToFormatModel(*s)
	if err := setProduct(bom, o); err != nil {
		return nil, err
	}
	bom.Metadata.Lifecycles = &[]cyclonedx.Lifecycle{{Phase: Lifecycle}}
	addExtra(bom, o.Extra)
	enrichPackages(bom, s.Artifacts.Packages.Sorted(), o.NuGetCache)
	markDeclaredLicences(bom)
	applyLicences(bom, o.Licences)
	completeDependencies(bom)
	return bom, nil
}

// markDeclaredLicences labels the licences Syft read from package metadata as "declared": they are what the
// component's creator assigned (BSI TR-03183-2 "original licences"). A "concluded" licence needs a person's review,
// so it is never set here.
func markDeclaredLicences(bom *cyclonedx.BOM) {
	if bom.Components == nil {
		return
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.Licenses == nil {
			continue
		}
		for j := range *c.Licenses {
			l := &(*c.Licenses)[j]
			switch {
			case l.License != nil && l.License.Acknowledgement == "":
				l.License.Acknowledgement = cyclonedx.LicenseAcknowledgementDeclared
			case l.Expression != "" && l.Acknowledgement == nil:
				ack := cyclonedx.LicenseAcknowledgementDeclared
				l.Acknowledgement = &ack
			}
		}
	}
}

// completeDependencies gives every component a dependencies entry (empty when it depends on nothing known), as
// CycloneDX expects for leaves, and states how complete the graph is. The scan cannot prove it found everything, so
// the honest statement is "unknown".
func completeDependencies(bom *cyclonedx.BOM) {
	var refs []string
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		refs = append(refs, bom.Metadata.Component.BOMRef)
	}
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.Type != cyclonedx.ComponentTypeFile && c.BOMRef != "" {
				refs = append(refs, c.BOMRef)
			}
		}
	}

	var deps []cyclonedx.Dependency
	if bom.Dependencies != nil {
		deps = *bom.Dependencies
	}
	have := map[string]bool{}
	for _, d := range deps {
		have[d.Ref] = true
	}
	for _, r := range refs {
		if !have[r] {
			deps = append(deps, cyclonedx.Dependency{Ref: r, Dependencies: &[]string{}})
			have[r] = true
		}
	}
	bom.Dependencies = &deps

	list := make([]cyclonedx.BOMReference, len(refs))
	for i, r := range refs {
		list[i] = cyclonedx.BOMReference(r)
	}
	bom.Compositions = &[]cyclonedx.Composition{{
		Aggregate:    cyclonedx.CompositionAggregateUnknown,
		Dependencies: &list,
	}}
}

// setProduct makes the product itself the SBOM's subject, instead of the scanned directory.
func setProduct(bom *cyclonedx.BOM, o Options) error {
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}
	supplier := &cyclonedx.OrganizationalEntity{Name: o.Manufacturer.Name}
	if o.Manufacturer.URL != "" {
		supplier.URL = &[]string{o.Manufacturer.URL}
	}
	if o.Manufacturer.Email != "" {
		supplier.Contact = &[]cyclonedx.OrganizationalContact{{Email: o.Manufacturer.Email}}
	}
	ref := "product"
	if bom.Metadata.Component != nil && bom.Metadata.Component.BOMRef != "" {
		// Keep Syft's reference: the dependency graph points at it.
		ref = bom.Metadata.Component.BOMRef
	}
	product := &cyclonedx.Component{
		BOMRef:       ref,
		Type:         cyclonedx.ComponentTypeApplication,
		Name:         o.Product,
		Version:      o.Version,
		Supplier:     supplier,
		Manufacturer: supplier,
	}
	if o.ProductLicence != "" {
		ack := cyclonedx.LicenseAcknowledgementConcluded
		product.Licenses = &cyclonedx.Licenses{{Expression: o.ProductLicence, Acknowledgement: &ack}}
	}
	setForm(product, o.ProductForm)
	if o.Artifact != "" {
		sum, err := fileSHA512(o.Artifact)
		if err != nil {
			return fmt.Errorf("artifact: %w", err)
		}
		addDeployable(product, o.ArtifactURL, filepath.Base(o.Artifact), sum)
	}
	bom.Metadata.Component = product
	bom.Metadata.Supplier = supplier
	bom.Metadata.Manufacturer = supplier
	return nil
}

func addExtra(bom *cyclonedx.BOM, extra []ExtraComponent) {
	if len(extra) == 0 {
		return
	}
	var comps []cyclonedx.Component
	if bom.Components != nil {
		comps = *bom.Components
	}
	var refs []string
	for _, e := range extra {
		c := e.toCycloneDX()
		comps = append(comps, c)
		refs = append(refs, c.BOMRef)
	}
	bom.Components = &comps

	// The product depends directly on every extra component.
	productRef := bom.Metadata.Component.BOMRef
	var deps []cyclonedx.Dependency
	if bom.Dependencies != nil {
		deps = *bom.Dependencies
	}
	found := false
	for i := range deps {
		if deps[i].Ref != productRef {
			continue
		}
		var on []string
		if deps[i].Dependencies != nil {
			on = *deps[i].Dependencies
		}
		on = append(on, refs...)
		sort.Strings(on)
		deps[i].Dependencies = &on
		found = true
	}
	if !found {
		sort.Strings(refs)
		deps = append(deps, cyclonedx.Dependency{Ref: productRef, Dependencies: &refs})
	}
	bom.Dependencies = &deps
}

// Write encodes the SBOM as CycloneDX 1.6 JSON.
func Write(w io.Writer, bom *cyclonedx.BOM) error {
	enc := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	return enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6)
}

// Count returns the number of components in the SBOM.
func Count(bom *cyclonedx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}
