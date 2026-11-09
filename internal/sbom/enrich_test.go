package sbom

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func property(c cyclonedx.Component, name string) string {
	if c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func distribution(c cyclonedx.Component) *cyclonedx.ExternalReference {
	for _, r := range derefRefs(c.ExternalReferences) {
		if r.Type == cyclonedx.ERTypeDistribution {
			return &r
		}
	}
	return nil
}

func TestSRISHA512(t *testing.T) {
	// sha512 of "" in SRI form, after an sha1 value as yarn sometimes writes it.
	sri := "sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk= sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
	want := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if got := sriSHA512(sri); got != want {
		t.Errorf("sriSHA512 = %q", got)
	}
	if got := sriSHA512("sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk="); got != "" {
		t.Errorf("sha1 only = %q, want empty", got)
	}
}

func writeFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for p, content := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnrichPackages(t *testing.T) {
	cache := t.TempDir()
	dir := filepath.Join(cache, "messagepack", "3.1.12")
	writeFiles(t, map[string]string{
		filepath.Join(dir, "messagepack.3.1.12.nupkg"): "nupkg bytes",
		filepath.Join(dir, ".nupkg.metadata"):          `{"version":2,"contentHash":"not the file hash","source":"https://api.nuget.org/v3/index.json"}`,
		filepath.Join(dir, "messagepack.nuspec"): "\xef\xbb\xbf<?xml version=\"1.0\"?>\n" +
			`<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>` +
			`<id>MessagePack</id><authors>neuecc,aarnott</authors><license type="expression">MIT</license>` +
			`<projectUrl>https://github.com/MessagePack-CSharp/MessagePack-CSharp</projectUrl>` +
			`<repository type="git" url="https://github.com/MessagePack-CSharp/MessagePack-CSharp.git" commit="abc" />` +
			`</metadata></package>`,
		// Restored from another feed: the hash is known, the download URL is not.
		filepath.Join(cache, "private.lib", "1.0.0", "private.lib.1.0.0.nupkg"): "private bytes",
		filepath.Join(cache, "private.lib", "1.0.0", ".nupkg.metadata"):         `{"source":"https://feed.example.com/v3/index.json"}`,
	})
	sum := sha512.Sum512([]byte("nupkg bytes"))
	wantHash := hex.EncodeToString(sum[:])

	pkgs := []pkg.Package{
		{Name: "MessagePack", Version: "3.1.12", PURL: "pkg:nuget/MessagePack@3.1.12", Metadata: pkg.DotnetPackagesLockEntry{Type: "Transitive"}},
		{Name: "Private.Lib", Version: "1.0.0", PURL: "pkg:nuget/Private.Lib@1.0.0", Metadata: pkg.DotnetPackagesLockEntry{Type: "Direct"}},
		{Name: "NotRestored", Version: "2.0.0", PURL: "pkg:nuget/NotRestored@2.0.0", Metadata: pkg.DotnetPackagesLockEntry{Type: "Direct"}},
		{Name: "app.rules", Version: "UNKNOWN", PURL: "pkg:nuget/app.rules@UNKNOWN", Metadata: pkg.DotnetPackagesLockEntry{Type: "Project"}},
		{Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0", Metadata: pkg.YarnLockEntry{
			Resolved:  "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e",
			Integrity: "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==",
		}},
	}
	var comps []cyclonedx.Component
	for i := range pkgs {
		pkgs[i].SetID()
		comps = append(comps, cyclonedx.Component{BOMRef: bomRef(pkgs[i]), Type: cyclonedx.ComponentTypeLibrary, Name: pkgs[i].Name, Version: pkgs[i].Version, PackageURL: pkgs[i].PURL})
	}
	maker := &cyclonedx.OrganizationalEntity{Name: "Maker", URL: &[]string{"https://example.com"}}
	ack := cyclonedx.LicenseAcknowledgementConcluded
	bom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{Component: &cyclonedx.Component{
			BOMRef: "product", Name: "App", Version: "2.0.0", Manufacturer: maker,
			Licenses: &cyclonedx.Licenses{{Expression: "LicenseRef-maker-proprietary", Acknowledgement: &ack}},
		}},
		Components: &comps,
	}

	enrichPackages(bom, pkgs, cache)
	mp, private, missing, project, pad := comps[0], comps[1], comps[2], comps[3], comps[4]

	d := distribution(mp)
	if d == nil || d.URL != "https://api.nuget.org/v3-flatcontainer/messagepack/3.1.12/messagepack.3.1.12.nupkg" || (*d.Hashes)[0].Value != wantHash {
		t.Errorf("MessagePack distribution = %+v", d)
	}
	if got := property(mp, propFilename); got != "messagepack.3.1.12.nupkg" {
		t.Errorf("MessagePack filename = %q", got)
	}
	if mp.Manufacturer == nil || mp.Manufacturer.Name != "neuecc,aarnott" || (*mp.Manufacturer.URL)[0] != "https://github.com/MessagePack-CSharp/MessagePack-CSharp" {
		t.Errorf("MessagePack manufacturer = %+v", mp.Manufacturer)
	}
	if !hasRefType(&mp, cyclonedx.ERTypeSourceDistribution) {
		t.Error("MessagePack has no source reference")
	}
	if l := (*mp.Licenses)[0].License; l == nil || l.ID != "MIT" || l.Acknowledgement != cyclonedx.LicenseAcknowledgementDeclared {
		t.Errorf("MessagePack licence = %+v", (*mp.Licenses)[0])
	}
	for name, want := range map[string]string{propExecutable: "non-executable", propArchive: "archive", propStructured: "structured"} {
		if got := property(mp, name); got != want {
			t.Errorf("MessagePack %s = %q, want %q", name, got, want)
		}
	}

	if distribution(private) != nil || !hasHash(private.Hashes, cyclonedx.HashAlgoSHA512) {
		t.Errorf("private feed: distribution %+v, hashes %+v; want no URL but a component hash", distribution(private), private.Hashes)
	}
	if missing.Hashes != nil || property(missing, propFilename) != "" {
		t.Error("a package that is not restored got a hash or filename")
	}

	if project.Version != "2.0.0" || project.Manufacturer != maker || !HasConcluded(project) {
		t.Errorf("project = version %q, manufacturer %+v, licences %+v", project.Version, project.Manufacturer, project.Licenses)
	}
	if got := property(project, propArchive); got != "no archive" {
		t.Errorf("project archive = %q", got)
	}

	if d := distribution(pad); d == nil || d.URL != "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz" {
		t.Errorf("left-pad distribution = %+v", d)
	}
	if got := property(pad, propFilename); got != "left-pad-1.3.0.tgz" {
		t.Errorf("left-pad filename = %q", got)
	}
}
