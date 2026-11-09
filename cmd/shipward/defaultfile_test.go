package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFiles writes name -> content below dir.
func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Without --config, the commands read shipward.yaml from the working directory.
func TestDefaultConfigFile(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"shipward.yaml":      "product:\n  name: App\nmanufacturer:\n  name: Maker\n",
		"sbom/sbom.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
	})
	t.Chdir(dir)

	var stdout, stderr bytes.Buffer
	if code := runLicences(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// An old cra.yaml next to a missing shipward.yaml stops the run with a clear message, so its settings and
// decisions are never ignored without a word, and init does not write a second, empty settings file.
func TestOldConfigFileName(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"cra.yaml":           "product:\n  name: App\nmanufacturer:\n  name: Maker\n",
		"sbom/sbom.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
	})
	t.Chdir(dir)

	var stdout, stderr bytes.Buffer
	if code := runLicences(nil, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "rename it to shipward.yaml") {
		t.Errorf("licences: exit %d, stderr %q; want an error that says to rename cra.yaml", code, stderr.String())
	}

	stderr.Reset()
	code := runInit([]string{"--product", "App", "--manufacturer", "Maker"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "rename it to shipward.yaml") {
		t.Errorf("init: exit %d, stderr %q; want an error that says to rename cra.yaml", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "shipward.yaml")); err == nil {
		t.Error("init wrote shipward.yaml next to cra.yaml")
	}
}
