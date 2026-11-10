package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/scan"
	"github.com/getshipward/shipward/internal/vex"
)

// triageProject writes shipward.yaml and an SBOM whose serial number is serial. The cache points at an empty folder,
// so the export finds no cached snapshot (no aliases) and makes no request.
func triageProject(t *testing.T, dir, serial string) string {
	t.Helper()
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	writeFiles(t, dir, map[string]string{
		"shipward.yaml": "product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n",
		"sbom/sbom.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:` + serial + `","version":1,
			"metadata":{"component":{"bom-ref":"product","type":"application","name":"Example Game","version":"1.4.0"}},
			"components":[{"type":"library","name":"Lib","version":"1.0.0","purl":"pkg:nuget/Lib@1.0.0"}]}`,
	})
	return filepath.Join(dir, "shipward.yaml")
}

func TestTriageSetByUpstream(t *testing.T) {
	dir := t.TempDir()
	cfg := triageProject(t, dir, "3e671687-395b-41f5-a30f-a58921a69b79")
	var stdout, stderr bytes.Buffer
	set := func(extra ...string) {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		args := append([]string{"set", "GHSA-1", "pkg:nuget/Lib@1.0.0", "--config", cfg}, extra...)
		if code := runTriage(context.Background(), args, &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
	}

	// affected without --by and without upstream: a warning and the Art. 13(6) hint.
	set("--status", "affected", "--action", "Update to 2.0.0.")
	if !strings.Contains(stderr.String(), "warning: no --by") || !strings.Contains(stdout.String(), "CRA Art. 13(6)") {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}

	// With --by and upstream flags: no warning, no hint, the fields in vex.yaml.
	set("--status", "affected", "--action", "Update to 2.0.0.", "--by", "alex", "--upstream-reported", "2026-11-07",
		"--upstream-link", "https://github.com/lib/lib/issues/4", "--upstream-fix-shared")
	if stderr.Len() != 0 || strings.Contains(stdout.String(), "Art. 13(6)") {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}

	// A later decision without upstream flags keeps them.
	set("--status", "fixed", "--by", "alex", "--date", "2026-11-09T10:00:00+01:00")
	list, err := vex.Load(filepath.Join(dir, "vex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Status != vex.Fixed || list[0].Date != "2026-11-09T10:00:00+01:00" || list[0].Upstream == nil ||
		list[0].Upstream.Link != "https://github.com/lib/lib/issues/4" || !list[0].Upstream.FixShared {
		t.Errorf("vex.yaml = %+v", list)
	}
	// One upstream flag changes only its own field.
	set("--status", "fixed", "--by", "alex", "--upstream-fix-shared=false")
	if list, _ = vex.Load(filepath.Join(dir, "vex.yaml")); list[0].Upstream == nil || list[0].Upstream.FixShared ||
		list[0].Upstream.Reported != "2026-11-07" || list[0].Upstream.Link != "https://github.com/lib/lib/issues/4" {
		t.Errorf("after --upstream-fix-shared=false: %+v", list[0].Upstream)
	}
	set("--status", "fixed", "--by", "alex", "--upstream-fix-shared")
	list, _ = vex.Load(filepath.Join(dir, "vex.yaml"))
	if got := decisionText(scanFinding(list[0])); !strings.Contains(got, "upstream: reported 2026-11-07, https://github.com/lib/lib/issues/4, fix shared") {
		t.Errorf("decision text = %q", got)
	}

	// A bad upstream date is refused.
	stderr.Reset()
	args := []string{"set", "GHSA-1", "pkg:nuget/Lib@1.0.0", "--config", cfg, "--status", "fixed", "--by", "alex", "--upstream-reported", "soon"}
	if code := runTriage(context.Background(), args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "upstream.reported") {
		t.Errorf("bad date: exit %d, %s", code, stderr.String())
	}
}

func TestTriageExportStableID(t *testing.T) {
	dir := t.TempDir()
	cfg := triageProject(t, dir, "3e671687-395b-41f5-a30f-a58921a69b79")
	writeFiles(t, dir, map[string]string{"vex.yaml": "- id: GHSA-1\n  component: pkg:nuget/Lib@1.0.0\n  status: fixed\n  by: alex\n  date: \"2026-11-06\"\n"})
	out := filepath.Join(dir, "sbom", "vex.openvex.json")
	export := func() vex.Document {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := runTriage(context.Background(), []string{"export", "--config", cfg}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		var doc vex.Document
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	var stderr bytes.Buffer
	if code := runTriage(context.Background(), []string{"export", "--config", cfg}, &bytes.Buffer{}, &stderr); code != 0 ||
		!strings.Contains(stderr.String(), "no earlier document at "+out+": this one starts at version 1") {
		t.Fatalf("first export: exit %d, stderr %q", code, stderr.String())
	}
	first := export()
	if p := first.Statements[0].Products[0].ID; p != "pkg:generic/Example%20Game@1.4.0" || first.Version != 1 {
		t.Fatalf("product %s, version %d", p, first.Version)
	}

	// A new SBOM run (another serial number) with the same decisions: the same document.
	triageProject(t, dir, "11111111-2222-3333-4444-555555555555")
	if again := export(); again.ID != first.ID || again.Version != 1 || again.Statements[0].Products[0].ID != first.Statements[0].Products[0].ID {
		t.Errorf("new serial: id %s (was %s), version %d", again.ID, first.ID, again.Version)
	}

	// A changed decision: version 2.
	writeFiles(t, dir, map[string]string{"vex.yaml": "- id: GHSA-1\n  component: pkg:nuget/Lib@1.0.0\n  status: under_investigation\n  by: alex\n  date: \"2026-11-07T08:00:00Z\"\n"})
	if changed := export(); changed.ID != first.ID || changed.Version != 2 || changed.LastUpdated == "" {
		t.Errorf("changed: id %s version %d last_updated %q", changed.ID, changed.Version, changed.LastUpdated)
	}
}

func scanFinding(s vex.Statement) scan.Finding {
	return scan.Finding{ID: s.ID, PURL: s.Component, State: s.Status, Decision: &s}
}

func TestProductID(t *testing.T) {
	cfg := &config.Config{Product: config.Product{Name: "App"}}
	for _, tc := range []struct {
		comp *cyclonedx.Component
		want string
	}{
		{&cyclonedx.Component{Name: "Game", Version: "1.4.0"}, "pkg:generic/Game@1.4.0"},
		{&cyclonedx.Component{Name: "Game", Version: "1.4.0", PackageURL: "pkg:github/maker/game@v1.4.0"}, "pkg:github/maker/game@v1.4.0"},
		{&cyclonedx.Component{Name: "Game", Version: "1.4.0", PackageURL: "pkg:github/maker/game"}, "pkg:github/maker/game@1.4.0"},
		{nil, "pkg:generic/App"},
	} {
		bom := &cyclonedx.BOM{Metadata: &cyclonedx.Metadata{Component: tc.comp}}
		if got := productID(bom, cfg); got != tc.want {
			t.Errorf("productID(%+v) = %s, want %s", tc.comp, got, tc.want)
		}
	}
}
