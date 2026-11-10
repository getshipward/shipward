package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestLoadExtraMissingFile(t *testing.T) {
	got, err := LoadExtra(filepath.Join(t.TempDir(), "components.extra.yaml"))
	if err != nil || got != nil {
		t.Fatalf("LoadExtra(missing) = %v, %v; want nil, nil", got, err)
	}
}

func TestLoadExtraValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "components.extra.yaml")
	data := "components:\n  - name: godot\n  - version: '1'\n    type: gadget\n    hashes: {md5: abc}\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadExtra(path)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"components[0]: version is required", "components[1]: name is required", `unknown type "gadget"`, `unknown hash algorithm "md5"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	// A tiny Go module with one dependency, and a workflow file that must stay out of the SBOM.
	files := map[string]string{
		"go.mod":                   "module example.com/app\n\ngo 1.26\n\nrequire golang.org/x/text v0.20.0\n",
		"go.sum":                   "golang.org/x/text v0.20.0 h1:gK/Kv2otX8gz+wn7Rmb3vT96ZwuoxnQlY+HlJVj7Qug=\ngolang.org/x/text v0.20.0/go.mod h1:D4IsuqiFMhST5bX19pQ9ikHC2GsaKyk/oF+pn3ducp4=\n",
		".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n",
		// An npm lock file with one dependency and one development dependency, which must stay out.
		"web/package-lock.json": `{"name":"web","lockfileVersion":3,"packages":{
			"":{"name":"web","dependencies":{"left-pad":"1.3.0"},"devDependencies":{"test-only":"1.0.0"}},
			"node_modules/left-pad":{"version":"1.3.0"},
			"node_modules/test-only":{"version":"1.0.0","dev":true}}}`,
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	bom, err := Generate(context.Background(), Options{
		Path:         dir,
		Exclude:      []string{"./.github/**"},
		Product:      "App",
		Version:      "1.2.3",
		Manufacturer: Supplier{Name: "Example s.p.", URL: "https://example.com", Email: "sec@example.com"},
		Extra: []ExtraComponent{{
			Name: "godot", Version: "4.7.2-stable", Type: "framework", PURL: "pkg:github/godotengine/godot@4.7.2-stable",
			Supplier: "Godot Foundation", Licenses: []string{"MIT"}, Hashes: map[string]string{"sha256": "00"},
		}},
		ToolVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Write(&buf, bom); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Lifecycles []struct {
				Phase string `json:"phase"`
			} `json:"lifecycles"`
			Component struct {
				BOMRef   string `json:"bom-ref"`
				Name     string `json:"name"`
				Version  string `json:"version"`
				Supplier struct {
					Name string `json:"name"`
				} `json:"supplier"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", doc.SpecVersion)
	}
	m := doc.Metadata.Component
	if m.Name != "App" || m.Version != "1.2.3" || m.Supplier.Name != "Example s.p." {
		t.Errorf("metadata.component = %+v", m)
	}

	if l := doc.Metadata.Lifecycles; len(l) != 1 || l[0].Phase != "pre-build" {
		t.Errorf("lifecycles = %+v; want one, pre-build (a source SBOM)", l)
	}

	var sawText, sawGodot, sawLeftPad bool
	for _, c := range doc.Components {
		switch {
		case c.Name == "left-pad":
			sawLeftPad = true
		case c.Name == "test-only":
			t.Error("npm development dependency is in the SBOM")
		case c.Name == "golang.org/x/text" && c.Version == "v0.20.0":
			sawText = true
		case c.Name == "godot" && c.PURL == "pkg:github/godotengine/godot@4.7.2-stable":
			sawGodot = true
		case strings.HasPrefix(c.PURL, "pkg:github/actions/"):
			t.Errorf("workflow action %s is in the SBOM", c.PURL)
		}
	}
	if !sawText || !sawGodot || !sawLeftPad {
		t.Errorf("components: x/text %v, godot %v, left-pad %v; want all", sawText, sawGodot, sawLeftPad)
	}

	var linked bool
	for _, d := range doc.Dependencies {
		if d.Ref != m.BOMRef {
			continue
		}
		for _, on := range d.DependsOn {
			if on == "pkg:github/godotengine/godot@4.7.2-stable" {
				linked = true
			}
		}
	}
	if !linked {
		t.Error("product does not depend on the extra component")
	}
}

func TestAddExtraWithoutPURL(t *testing.T) {
	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: "product"}}
	addExtra(bom, []ExtraComponent{{Name: "vendored-zlib", Version: "1.3.1"}})
	if got := (*bom.Components)[0].BOMRef; got != "extra:vendored-zlib@1.3.1" {
		t.Errorf("BOMRef = %q", got)
	}
	if got := *(*bom.Dependencies)[0].Dependencies; len(got) != 1 || got[0] != "extra:vendored-zlib@1.3.1" {
		t.Errorf("dependencies = %q", got)
	}
}

func TestCompleteDependenciesAndDeclaredLicences(t *testing.T) {
	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: "product"}}
	bom.Components = &[]cyclonedx.Component{
		{BOMRef: "a", Name: "a", Licenses: &cyclonedx.Licenses{{License: &cyclonedx.License{ID: "MIT"}}}},
		{BOMRef: "b", Name: "b", Licenses: &cyclonedx.Licenses{{Expression: "MIT OR Apache-2.0"}}},
		{BOMRef: "f", Name: "f.txt", Type: cyclonedx.ComponentTypeFile},
	}
	bom.Dependencies = &[]cyclonedx.Dependency{{Ref: "product", Dependencies: &[]string{"a"}}}

	markDeclaredLicences(bom)
	completeDependencies(bom)

	comps := *bom.Components
	if got := comps[0].Licenses; (*got)[0].License.Acknowledgement != cyclonedx.LicenseAcknowledgementDeclared {
		t.Errorf("licence a not declared: %+v", (*got)[0].License)
	}
	if got := comps[1].Licenses; (*got)[0].Acknowledgement == nil || *(*got)[0].Acknowledgement != cyclonedx.LicenseAcknowledgementDeclared {
		t.Error("expression b not declared")
	}

	refs := map[string]bool{}
	for _, d := range *bom.Dependencies {
		refs[d.Ref] = true
	}
	for _, want := range []string{"product", "a", "b"} {
		if !refs[want] {
			t.Errorf("no dependencies entry for %s", want)
		}
	}
	if refs["f"] {
		t.Error("file component got a dependencies entry")
	}

	comp := (*bom.Compositions)[0]
	if comp.Aggregate != cyclonedx.CompositionAggregateUnknown || len(*comp.Dependencies) != 3 {
		t.Errorf("composition = %+v", comp)
	}
}
