package sbom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestLoadLicences(t *testing.T) {
	if got, err := LoadLicences(filepath.Join(t.TempDir(), "licences.yaml")); got != nil || err != nil {
		t.Fatalf("missing file = %v, %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "licences.yaml")
	data := "- component: pkg:npm/a@1.0.0\n- component: pkg:npm/b\n  concluded: MIT\n- concluded: MIT\n" +
		"- component: pkg:npm/c@1.0.0\n  concluded: All rights reserved\n- component: pkg:npm/d@1.0.0\n  concluded: LicenseRef-x-own OR MIT\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLicences(path)
	for _, want := range []string{"pkg:npm/a@1.0.0: concluded is required", "pkg:npm/b: an entry for every version needs the declared licence",
		"entry 2: component is required", `pkg:npm/c@1.0.0: concluded "All rights reserved" is not an SPDX licence expression`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "pkg:npm/d@1.0.0") {
		t.Errorf("LicenseRef expression refused: %v", err)
	}
	if _, err := Generate(context.Background(), Options{Path: t.TempDir(), ProductLicence: "Proprietary"}); err == nil ||
		!strings.Contains(err.Error(), `product.licence "Proprietary" is not an SPDX licence expression`) {
		t.Errorf("Generate with a non-SPDX product licence: %v", err)
	}
}

func declared(id string) *cyclonedx.Licenses {
	return &cyclonedx.Licenses{{License: &cyclonedx.License{ID: id, Acknowledgement: cyclonedx.LicenseAcknowledgementDeclared}}}
}

func TestApplyLicences(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "a", Version: "1.0.0", PackageURL: "pkg:npm/a@1.0.0?arch=x", Licenses: declared("MIT")},
		{Name: "b", Version: "2.0.0", PackageURL: "pkg:npm/b@2.0.0", Licenses: declared("BSL-1.0")}, // declared changed
		{Name: "c", Version: "3.0.0", PackageURL: "pkg:npm/c@3.0.0", Licenses: declared("MIT")},
		{Name: "vendored", Version: "1.0", Licenses: declared("Zlib")},
	}}
	applyLicences(bom, []LicenceConfirmation{
		{Component: "pkg:npm/a", Declared: "MIT", Concluded: "MIT"},
		{Component: "pkg:npm/b", Declared: "MIT", Concluded: "MIT"},
		{Component: "pkg:npm/c@3.0.0", Concluded: "MIT OR Apache-2.0"},
		{Component: "vendored@1.0", Concluded: "Zlib"},
	})
	a, b, c, v := (*bom.Components)[0], (*bom.Components)[1], (*bom.Components)[2], (*bom.Components)[3]
	if !HasConcluded(a) || len(*a.Licenses) != 2 || (*a.Licenses)[0].License.Acknowledgement != cyclonedx.LicenseAcknowledgementDeclared {
		t.Errorf("a: %+v; want declared kept and concluded added", *a.Licenses)
	}
	if HasConcluded(b) {
		t.Error("b: confirmed although its declared licence changed")
	}
	if got := *c.Licenses; len(got) != 1 || got[0].Expression != "MIT OR Apache-2.0" {
		t.Errorf("c: %+v; want the one concluded expression (CycloneDX 1.6 allows one)", got)
	}
	if !HasConcluded(v) {
		t.Error("component without purl not confirmed by name@version")
	}
}

func TestSetConcludedKeepsPlainDeclaredExpression(t *testing.T) {
	ack := cyclonedx.LicenseAcknowledgementDeclared
	c := cyclonedx.Component{Licenses: &cyclonedx.Licenses{{Expression: "Apache-2.0", Acknowledgement: &ack}}}
	setConcluded(&c, "Apache-2.0")
	if got := *c.Licenses; len(got) != 2 || got[0].License == nil || got[0].License.ID != "Apache-2.0" || got[1].License.Acknowledgement != cyclonedx.LicenseAcknowledgementConcluded {
		t.Errorf("licences = %+v", got)
	}
}

func TestDeclaredLicence(t *testing.T) {
	ack := cyclonedx.LicenseAcknowledgementDeclared
	c := cyclonedx.Component{Licenses: &cyclonedx.Licenses{
		{License: &cyclonedx.License{ID: "MIT", Acknowledgement: ack}},
		{License: &cyclonedx.License{ID: "Apache-2.0", Acknowledgement: ack}},
	}}
	if got := DeclaredLicence(c); got != "Apache-2.0 AND MIT" {
		t.Errorf("DeclaredLicence = %q", got)
	}
}

func TestExtraLicences(t *testing.T) {
	if got := *extraLicences([]string{"MIT", "Zlib"}); len(got) != 2 || got[1].License.ID != "Zlib" {
		t.Errorf("plain IDs = %+v", got)
	}
	if got := *extraLicences([]string{"MIT", "GPL-2.0-only WITH Classpath-exception-2.0"}); len(got) != 1 || got[0].Expression != "MIT AND (GPL-2.0-only WITH Classpath-exception-2.0)" {
		t.Errorf("mixed = %+v", got)
	}
	if got := *extraLicences([]string{"LicenseRef-acme-eula"}); got[0].Expression != "LicenseRef-acme-eula" {
		t.Errorf("LicenseRef = %+v", got)
	}
}
