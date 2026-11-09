package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicencesWrite(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"cra.yaml": "product:\n  name: App\nmanufacturer:\n  name: Maker\n",
		"sbom/sbom.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
			{"type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0","licenses":[{"license":{"id":"MIT","acknowledgement":"declared"}}]},
			{"type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0","licenses":[{"license":{"id":"MIT","acknowledgement":"declared"}}]},
			{"type":"library","name":"b","version":"2.0.0","purl":"pkg:npm/b@2.0.0"},
			{"type":"library","name":"c","version":"3.0.0","purl":"pkg:npm/c@3.0.0","licenses":[{"license":{"id":"MIT","acknowledgement":"concluded"}}]}]}`,
		"licences.yaml": "# kept\n",
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

	var stdout, stderr bytes.Buffer
	if code := runLicences([]string{"--config", filepath.Join(dir, "cra.yaml"), "--write"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, "licences.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# kept\n- component: pkg:npm/a\n  declared: MIT\n  concluded: MIT\n"
	if string(got) != want {
		t.Errorf("licences.yaml =\n%s\nwant\n%s", got, want)
	}
	if out := stdout.String(); !strings.Contains(out, "added 1 entries") || !strings.Contains(out, "b@2.0.0 (declared: none)") {
		t.Errorf("stdout = %q", out)
	}
}
