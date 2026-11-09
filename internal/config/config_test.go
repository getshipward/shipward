package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cra.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	path := write(t, "product:\n  name: Example Game\nmanufacturer:\n  name: Example s.p.\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SBOM.Path != "." || c.SBOM.Output != "sbom/sbom.cdx.json" || c.SBOM.Extra != "components.extra.yaml" || c.SBOM.Licences != "licences.yaml" {
		t.Errorf("defaults = %+v", c.SBOM)
	}
	if got := c.SBOM.Exclude; len(got) != 1 || got[0] != "./.github/**" {
		t.Errorf("Exclude = %q, want only ./.github/**", got)
	}
	if got, want := c.Resolve("sbom/x.json"), filepath.Join(filepath.Dir(path), "sbom/x.json"); got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
	if got := c.Resolve("/abs/x.json"); got != "/abs/x.json" {
		t.Errorf("Resolve(abs) = %q", got)
	}
}

func TestLoadRequiredFields(t *testing.T) {
	_, err := Load(write(t, "sbom:\n  path: src\n"))
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"product.name", "manufacturer.name"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestLoadUnknownFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("want an error")
	}
}

func TestSecurityDefaultsAndChecks(t *testing.T) {
	c, err := Load(write(t, "product:\n  name: A\n  support_until: \"2031-12\"\nmanufacturer:\n  name: M\n  email: m@example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Security.Contact != "mailto:m@example.com" || c.Security.Languages[0] != "en" || c.Docs.Dir != "cra" {
		t.Errorf("defaults = %+v %+v", c.Security, c.Docs)
	}
	_, err = Load(write(t, "product:\n  name: A\n  support_until: 2031\nmanufacturer:\n  name: M\nsecurity:\n  contact: sec@example.com\n"))
	for _, want := range []string{"support_until", "security.contact"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not name %s", err, want)
		}
	}
}
