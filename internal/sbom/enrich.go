package sbom

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

// BSI TR-03183-2 v2.1.0 property names (section 8.2).
const (
	propFilename   = "bsi:component:filename"
	propExecutable = "bsi:component:executable"
	propArchive    = "bsi:component:archive"
	propStructured = "bsi:component:structured"
)

// packageArchives are the purl types whose deployable form is a package file: an archive with metadata that names its
// contents. TR-03183-2 table 7 rates such a package (its example is an rpm) non-executable, archive, structured.
var packageArchives = map[string]bool{
	packageurl.TypeNPM:      true,
	packageurl.TypeNuget:    true,
	packageurl.TypeComposer: true,
	packageurl.TypeGolang:   true,
	packageurl.TypeGem:      true,
	packageurl.TypePyPi:     true,
	packageurl.TypeCargo:    true,
}

// nugetOrg is the service index of nuget.org as NuGet records it in .nupkg.metadata.
const nugetOrg = "https://api.nuget.org/v3/index.json"

// enrichPackages adds the BSI fields that local files state as facts: the package form of registry packages, and the
// download URL, SHA-512, filename, creator and source of packages whose lock file or local package cache records them.
// It reads only local files; nothing is looked up online.
func enrichPackages(bom *cyclonedx.BOM, pkgs []pkg.Package, nugetCache string) {
	if bom.Components == nil {
		return
	}
	byRef := make(map[string]pkg.Package, len(pkgs))
	for _, p := range pkgs {
		byRef[bomRef(p)] = p
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		p, ok := byRef[c.BOMRef]
		if m, isLock := p.Metadata.(pkg.DotnetPackagesLockEntry); ok && isLock && m.Type == "Project" {
			ownProject(c, bom.Metadata.Component)
			continue
		}
		if purl, err := packageurl.FromString(c.PackageURL); err == nil && packageArchives[purl.Type] {
			setForm(c, Form{Executable: ptr(false), Archive: ptr(true), Structured: ptr(true)})
		}
		if !ok {
			continue
		}
		switch m := p.Metadata.(type) {
		case pkg.NpmPackageLockEntry:
			addTarball(c, m.Resolved, m.Integrity)
		case pkg.YarnLockEntry:
			addTarball(c, m.Resolved, m.Integrity)
		case pkg.PnpmLockEntry:
			addTarball(c, "", m.Resolution.Integrity)
		case pkg.DotnetPackagesLockEntry:
			if nugetCache != "" {
				addNuGet(c, p.Name, p.Version, nugetCache)
			}
		}
	}
}

// ownProject fills a .NET project reference: a project in the scanned source tree, built into the product from the
// same source at the same release. It takes the product's creator, version and licence. As a built .dll it is
// executable, not an archive, and holds no other components (TR-03183-2 table 7 rates a script the same way).
func ownProject(c *cyclonedx.Component, product *cyclonedx.Component) {
	if product == nil {
		return
	}
	if c.Manufacturer == nil {
		c.Manufacturer = product.Manufacturer
	}
	if (c.Version == "" || c.Version == "UNKNOWN") && product.Version != "" {
		c.Version = product.Version
	}
	if c.Licenses == nil && product.Licenses != nil {
		lic := append(cyclonedx.Licenses(nil), *product.Licenses...)
		c.Licenses = &lic
	}
	setForm(c, Form{Executable: ptr(true), Archive: ptr(false), Structured: ptr(false)})
}

// bomRef is the bom-ref Syft gives a package in CycloneDX (helpers.DeriveBomRef in Syft, an internal package).
func bomRef(p pkg.Package) string {
	if purl, err := packageurl.FromString(p.PURL); err == nil {
		purl.Qualifiers = append(purl.Qualifiers, packageurl.Qualifier{Key: "package-id", Value: string(p.ID())})
		return purl.ToString()
	}
	return string(p.ID())
}

// addTarball records a JavaScript package tarball. The lock file's integrity value is the SHA-512 of the tarball as
// downloaded, so it is the hash of the deployable file.
func addTarball(c *cyclonedx.Component, resolved, integrity string) {
	sum := sriSHA512(integrity)
	if sum == "" {
		return
	}
	u, err := url.Parse(resolved)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		u = nil
	}
	filename := ""
	if u != nil {
		filename = path.Base(u.Path)
	}
	addDeployable(c, resolvedURL(u), filename, sum)
}

func resolvedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	u.Fragment = "" // yarn appends "#<sha1>"
	return u.String()
}

// sriSHA512 returns the hex SHA-512 from a Subresource Integrity value ("sha512-<base64>", possibly among others).
func sriSHA512(sri string) string {
	for _, part := range strings.Fields(sri) {
		b64, ok := strings.CutPrefix(part, "sha512-")
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != sha512.Size {
			return ""
		}
		return hex.EncodeToString(raw)
	}
	return ""
}

// addDeployable records the deployable file: its name, and its SHA-512 both as a component hash and, when the download
// URL is known, on the distribution reference (where TR-03183-2 maps the hash).
func addDeployable(c *cyclonedx.Component, downloadURL, filename, sha512hex string) {
	if filename != "" {
		setProperty(c, propFilename, filename)
	}
	hash := cyclonedx.Hash{Algorithm: cyclonedx.HashAlgoSHA512, Value: sha512hex}
	if sha512hex != "" && !hasHash(c.Hashes, cyclonedx.HashAlgoSHA512) {
		hashes := append(derefHashes(c.Hashes), hash)
		c.Hashes = &hashes
	}
	if downloadURL == "" {
		return
	}
	refs := derefRefs(c.ExternalReferences)
	i := 0
	for i < len(refs) && (refs[i].Type != cyclonedx.ERTypeDistribution || refs[i].URL != downloadURL) {
		i++
	}
	if i == len(refs) {
		refs = append(refs, cyclonedx.ExternalReference{Type: cyclonedx.ERTypeDistribution, URL: downloadURL})
	}
	if sha512hex != "" && !hasHash(refs[i].Hashes, cyclonedx.HashAlgoSHA512) {
		hashes := append(derefHashes(refs[i].Hashes), hash)
		refs[i].Hashes = &hashes
	}
	c.ExternalReferences = &refs
}

// addNuGet reads a restored package from the NuGet global packages folder. The lock file's contentHash cannot be
// used: for signed packages (all of nuget.org) NuGet hashes the content without the signature, not the .nupkg file.
func addNuGet(c *cyclonedx.Component, id, version, cache string) {
	lid, lver := strings.ToLower(id), strings.ToLower(version)
	dir := filepath.Join(cache, lid, lver)
	filename := lid + "." + lver + ".nupkg"
	sum, err := fileSHA512(filepath.Join(dir, filename))
	if err != nil {
		return // not restored on this machine
	}
	var meta struct {
		Source string `json:"source"`
	}
	if data, err := os.ReadFile(filepath.Join(dir, ".nupkg.metadata")); err == nil {
		_ = json.Unmarshal(data, &meta)
	}
	download := ""
	if meta.Source == nugetOrg {
		download = "https://api.nuget.org/v3-flatcontainer/" + lid + "/" + lver + "/" + filename
	}
	addDeployable(c, download, filename, sum)

	spec, err := readNuspec(filepath.Join(dir, lid+".nuspec"))
	if err != nil {
		return
	}
	project := spec.ProjectURL
	repo := strings.TrimSuffix(spec.Repository.URL, ".git")
	if project == "" {
		project = repo
	}
	if c.Manufacturer == nil && validURL(project) {
		c.Manufacturer = &cyclonedx.OrganizationalEntity{Name: spec.Authors, URL: &[]string{project}}
	}
	if validURL(repo) && !hasRefType(c, cyclonedx.ERTypeSourceDistribution) {
		refs := append(derefRefs(c.ExternalReferences), cyclonedx.ExternalReference{Type: cyclonedx.ERTypeSourceDistribution, URL: repo})
		c.ExternalReferences = &refs
	}
	if c.Licenses == nil && spec.License.Type == "expression" && spec.License.Value != "" {
		c.Licenses = &cyclonedx.Licenses{licenceChoice(spec.License.Value, cyclonedx.LicenseAcknowledgementDeclared)}
	}
}

type nuspec struct {
	Authors    string `xml:"metadata>authors"`
	ProjectURL string `xml:"metadata>projectUrl"`
	License    struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"metadata>license"`
	Repository struct {
		URL string `xml:"url,attr"`
	} `xml:"metadata>repository"`
}

func readNuspec(p string) (nuspec, error) {
	var s nuspec
	data, err := os.ReadFile(p)
	if err != nil {
		return s, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	err = xml.Unmarshal(data, &s)
	return s, err
}

func fileSHA512(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// DefaultNuGetCache is where dotnet restore puts packages: $NUGET_PACKAGES, else ~/.nuget/packages.
func DefaultNuGetCache() string {
	if d := os.Getenv("NUGET_PACKAGES"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".nuget", "packages")
}

// Form is what TR-03183-2 calls the executable, archive and structured properties of a component. Nil means unknown.
type Form struct {
	Executable *bool `yaml:"executable"`
	Archive    *bool `yaml:"archive"`
	Structured *bool `yaml:"structured"`
}

func setForm(c *cyclonedx.Component, f Form) {
	if f.Executable != nil {
		setProperty(c, propExecutable, choose(*f.Executable, "executable", "non-executable"))
	}
	if f.Archive != nil {
		setProperty(c, propArchive, choose(*f.Archive, "archive", "no archive"))
	}
	if f.Structured != nil {
		setProperty(c, propStructured, choose(*f.Structured, "structured", "unstructured"))
	}
}

// setProperty adds a property unless the component already has one with that name.
func setProperty(c *cyclonedx.Component, name, value string) {
	var props []cyclonedx.Property
	if c.Properties != nil {
		props = *c.Properties
	}
	for _, p := range props {
		if p.Name == name {
			return
		}
	}
	props = append(props, cyclonedx.Property{Name: name, Value: value})
	c.Properties = &props
}

func hasRefType(c *cyclonedx.Component, typ cyclonedx.ExternalReferenceType) bool {
	for _, r := range derefRefs(c.ExternalReferences) {
		if r.Type == typ {
			return true
		}
	}
	return false
}

func hasHash(hashes *[]cyclonedx.Hash, alg cyclonedx.HashAlgorithm) bool {
	for _, h := range derefHashes(hashes) {
		if h.Algorithm == alg {
			return true
		}
	}
	return false
}

func derefHashes(h *[]cyclonedx.Hash) []cyclonedx.Hash {
	if h == nil {
		return nil
	}
	return *h
}

func derefRefs(r *[]cyclonedx.ExternalReference) []cyclonedx.ExternalReference {
	if r == nil {
		return nil
	}
	return *r
}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func choose(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func ptr[T any](v T) *T { return &v }
