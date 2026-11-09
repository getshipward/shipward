package scan

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/getshipward/shipward/internal/osv"
	"github.com/getshipward/shipward/internal/snapshot"
	"github.com/getshipward/shipward/internal/vex"
)

func gz(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.Bytes()
}

// localSnapshot writes a signed snapshot with two NuGet records into a folder and returns it and the public key.
func localSnapshot(t *testing.T) (string, string) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	vulns := []osv.Vulnerability{
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-0001"}, Summary: "Lib bug", Affected: []osv.Affected{{
			Package: osv.Package{Ecosystem: "NuGet", Name: "Lib"},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
		}}},
		{ID: "GHSA-bbbb", Aliases: []string{"CVE-2024-0002"}, Summary: "Other bug", Affected: []osv.Affected{{
			Package: osv.Package{Ecosystem: "NuGet", Name: "Other"},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "9.0.0"}}}},
		}}},
	}
	files := map[string][]byte{
		"run/osv-NuGet.json.gz": gz(t, vulns),
		"run/exploited.json.gz": gz(t, snapshot.Exploited{KEV: map[string]snapshot.KEV{"CVE-2024-0002": {Added: "2026-11-01"}}}),
	}
	idx := snapshot.Index{Format: snapshot.Format, Created: time.Now().UTC()}
	for p, data := range files {
		os.MkdirAll(filepath.Join(dir, "run"), 0o755)
		os.WriteFile(filepath.Join(dir, p), data, 0o644)
		h := sha256.Sum256(data)
		f := snapshot.File{Kind: "osv", Ecosystem: "NuGet", Path: p, SHA256: hex.EncodeToString(h[:]), Size: int64(len(data))}
		if p == "run/exploited.json.gz" {
			f.Kind, f.Ecosystem = "exploited", ""
		}
		idx.Files = append(idx.Files, f)
	}
	sealed, err := snapshot.Seal(key, idx)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "index.json"), sealed, 0o644)
	return dir, snapshot.PublicKey(key)
}

// liveCache pre-fills the EUVD and EPSS copies, so the test makes no requests.
func liveCache(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	live := filepath.Join(cache, "live")
	os.MkdirAll(live, 0o755)
	os.WriteFile(filepath.Join(live, "euvd.json"), []byte(`{}`), 0o644)
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte("cve,epss,percentile\nCVE-2024-0001,0.25,0.9\n"))
	w.Close()
	os.WriteFile(filepath.Join(live, "epss.csv.gz"), buf.Bytes(), 0o644)
	return cache
}

func TestRun(t *testing.T) {
	dir, pub := localSnapshot(t)
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Lib", Version: "1.0.0", PackageURL: "pkg:nuget/Lib@1.0.0"},
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Lib", Version: "1.0.0", PackageURL: "pkg:nuget/Lib@1.0.0?package-id=2"}, // same package twice
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Other", Version: "1.0.0", PackageURL: "pkg:nuget/Other@1.0.0"},
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Safe", Version: "3.0.0", PackageURL: "pkg:nuget/Lib@3.0.0"},
		{Type: cyclonedx.ComponentTypeFramework, Name: "godot", Version: "4.7.2-stable", PackageURL: "pkg:github/godotengine/godot@4.7.2-stable"},
	}}
	decisions := []vex.Statement{
		{ID: "CVE-2024-0001", Component: "pkg:nuget/Lib@1.0.0", Status: vex.NotAffected, Justification: "component_not_present", Date: "2026-11-06"},
		{ID: "GHSA-zzzz", Component: "pkg:nuget/Gone", Status: vex.Fixed, Date: "2026-11-01"},
	}
	rep, err := Run(context.Background(), Options{BOM: bom, Decisions: decisions, Snapshot: dir, Keys: []string{pub}, CacheDir: liveCache(t)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Checked != 3 || len(rep.NotChecked) != 1 || len(rep.Warnings) != 0 {
		t.Errorf("checked %d, not checked %q, warnings %q", rep.Checked, rep.NotChecked, rep.Warnings)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	// Open and exploited first, the decided one last.
	first, second := rep.Findings[0], rep.Findings[1]
	if first.ID != "GHSA-bbbb" || first.State != StateOpen || first.KEV != "2026-11-01" || !first.NeedsWork() {
		t.Errorf("first = %+v", first)
	}
	if second.ID != "GHSA-aaaa" || second.State != vex.NotAffected || second.EPSS == nil || second.EPSS.Score != 0.25 || second.NeedsWork() {
		t.Errorf("second = %+v (decision by alias CVE-2024-0001)", second)
	}
	if len(rep.Unused) != 1 || rep.Unused[0].ID != "GHSA-zzzz" {
		t.Errorf("unused = %+v", rep.Unused)
	}
}
