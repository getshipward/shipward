package check

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// full returns a component that meets every BSI rule.
func full(ref, name string) cyclonedx.Component {
	return cyclonedx.Component{
		BOMRef:       ref,
		Type:         cyclonedx.ComponentTypeLibrary,
		Name:         name,
		Version:      "1.0.0",
		PackageURL:   "pkg:generic/" + name + "@1.0.0",
		Manufacturer: &cyclonedx.OrganizationalEntity{Name: "Maker", URL: &[]string{"https://example.com"}},
		Licenses: &cyclonedx.Licenses{
			{License: &cyclonedx.License{ID: "MIT", Acknowledgement: cyclonedx.LicenseAcknowledgementDeclared}},
			{License: &cyclonedx.License{ID: "MIT", Acknowledgement: cyclonedx.LicenseAcknowledgementConcluded}},
		},
		ExternalReferences: &[]cyclonedx.ExternalReference{
			{Type: cyclonedx.ERTypeDistribution, URL: "https://example.com/" + name + ".zip",
				Hashes: &[]cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA512, Value: "ab"}}},
			{Type: cyclonedx.ERTypeSourceDistribution, URL: "https://example.com/src"},
		},
		Properties: &[]cyclonedx.Property{
			{Name: "bsi:component:filename", Value: name + ".zip"},
			{Name: "bsi:component:executable", Value: "non-executable"},
			{Name: "bsi:component:archive", Value: "archive"},
			{Name: "bsi:component:structured", Value: "structured"},
		},
	}
}

func fullBOM() *cyclonedx.BOM {
	product := full("product", "app")
	lib := full("lib", "lib")
	return &cyclonedx.BOM{
		SpecVersion:  cyclonedx.SpecVersion1_6,
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Metadata: &cyclonedx.Metadata{
			Timestamp:    "2026-11-06T12:00:00Z",
			Manufacturer: &cyclonedx.OrganizationalEntity{Name: "Maker", Contact: &[]cyclonedx.OrganizationalContact{{Email: "sec@example.com"}}},
			Component:    &product,
		},
		Components: &[]cyclonedx.Component{lib, {Type: cyclonedx.ComponentTypeFile, Name: "ignored.txt"}},
		Dependencies: &[]cyclonedx.Dependency{
			{Ref: "product", Dependencies: &[]string{"lib"}},
			{Ref: "lib"},
		},
		Compositions: &[]cyclonedx.Composition{{
			Aggregate:    cyclonedx.CompositionAggregateComplete,
			Dependencies: &[]cyclonedx.BOMReference{"product", "lib"},
		}},
	}
}

func byID(results []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range results {
		m[r.ID] = r
	}
	return m
}

func TestBSIAllPresent(t *testing.T) {
	for _, r := range BSI(fullBOM()) {
		if !r.OK() {
			t.Errorf("%s: %d of %d, failing %q", r.ID, r.Passed, r.Total, r.Failing)
		}
		if r.Total != 1 && r.Total != 2 {
			t.Errorf("%s: Total %d; want 1 (SBOM rule) or 2 (product + lib, file skipped)", r.ID, r.Total)
		}
	}
}

func TestBSIGaps(t *testing.T) {
	bom := fullBOM()
	bom.SpecVersion = cyclonedx.SpecVersion1_5
	bom.Metadata.Timestamp = "yesterday"
	bom.Metadata.Manufacturer = &cyclonedx.OrganizationalEntity{Name: "No contact"}
	bom.SerialNumber = ""
	lib := &(*bom.Components)[0]
	lib.Manufacturer = nil
	lib.Licenses = &cyclonedx.Licenses{{License: &cyclonedx.License{ID: "MIT"}}} // no acknowledgement
	lib.ExternalReferences = &[]cyclonedx.ExternalReference{{Type: cyclonedx.ERTypeDistribution, URL: "u",
		Hashes: &[]cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA256, Value: "ab"}}}}
	lib.Properties = &[]cyclonedx.Property{{Name: "bsi:component:archive", Value: "yes"}} // not an allowed value
	bom.Dependencies = &[]cyclonedx.Dependency{{Ref: "product", Dependencies: &[]string{"lib"}}}
	bom.Compositions = &[]cyclonedx.Composition{{
		Aggregate:    cyclonedx.CompositionAggregateNotSpecified,
		Dependencies: &[]cyclonedx.BOMReference{"product", "lib"},
	}}

	got := byID(BSI(bom))
	wantFailing := map[string][]string{
		"bsi.format":                     {"specVersion 1.5 is below 1.6"},
		"bsi.sbom.timestamp":             {`timestamp "yesterday" is not RFC 3339`},
		"bsi.sbom.creator":               {"manufacturer has no email and no URL"},
		"bsi.sbom.uri":                   {"no serialNumber"},
		"bsi.component.creator":          {"lib@1.0.0"},
		"bsi.component.licence":          {"lib@1.0.0"},
		"bsi.component.original-licence": {"lib@1.0.0"},
		"bsi.component.hash":             {"lib@1.0.0"},
		"bsi.component.source-uri":       {"lib@1.0.0"},
		"bsi.component.filename":         {"lib@1.0.0"},
		"bsi.component.archive":          {"lib@1.0.0"},
		"bsi.component.executable":       {"lib@1.0.0"},
		"bsi.component.structured":       {"lib@1.0.0"},
		"bsi.component.dependencies":     {"lib@1.0.0"},
		"bsi.component.completeness":     {"app@1.0.0", "lib@1.0.0"},
	}
	for id, want := range wantFailing {
		r, ok := got[id]
		if !ok {
			t.Errorf("%s: no result", id)
			continue
		}
		if len(r.Failing) != len(want) {
			t.Errorf("%s: failing %q, want %q", id, r.Failing, want)
			continue
		}
		for i := range want {
			if r.Failing[i] != want[i] {
				t.Errorf("%s: failing %q, want %q", id, r.Failing, want)
			}
		}
	}
	for id, r := range got {
		if _, listed := wantFailing[id]; !listed && !r.OK() {
			t.Errorf("%s: unexpected gap %q", id, r.Failing)
		}
	}
	if got["bsi.sbom.uri"].Level != MustIfExists || got["bsi.component.hash"].Level != Must {
		t.Error("wrong levels")
	}
}
