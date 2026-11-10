package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadBOMNamesOtherFormats(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"":                                      "the file is empty",
		`<?xml version="1.0"?><bom/>`:           "looks like XML",
		"SPDXVersion: SPDX-2.3\n":               "not JSON",
		`{"spdxVersion":"SPDX-2.3","name":"x"}`: "an SPDX SBOM (SPDX-2.3)",
		`{"name":"x"}`:                          `no "bomFormat": "CycloneDX"`,
		`{"bomFormat":"CycloneDX",`:             "not valid JSON",
		`{"bomFormat":"CycloneDX","specVersion":"1.6"}`: "",
	} {
		p := filepath.Join(dir, "sbom.json")
		os.WriteFile(p, []byte(content), 0o644)
		_, err := readBOM(p)
		switch {
		case want == "" && err != nil:
			t.Errorf("%q: %v", content, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "CycloneDX")):
			t.Errorf("%q: error %v, want %q", content, err, want)
		}
	}
}

func TestCheckPrintsVersionAndReminder(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sbom.json")
	os.WriteFile(p, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), 0o644)
	summary := filepath.Join(dir, "summary.md")
	var stdout, stderr bytes.Buffer
	runCheck([]string{"sbom", p, "--summary", summary}, &stdout, &stderr)
	sum, _ := os.ReadFile(summary)
	for name, out := range map[string]string{"text": stdout.String(), "summary": string(sum)} {
		for _, want := range []string{"BSI TR-03183-2 v2.1.0", "2025-08-20", "newer version of TR-03183-2"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, out)
			}
		}
	}
}
