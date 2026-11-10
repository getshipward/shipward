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
	"strings"
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

// localSnapshot writes a signed snapshot with three NuGet records into a folder and returns it and the public key.
func localSnapshot(t *testing.T) (string, string) {
	t.Helper()
	return localSnapshotAt(t, time.Now().UTC())
}

func localSnapshotAt(t *testing.T, created time.Time) (string, string) {
	t.Helper()
	return localSnapshotWith(t, created, snapshot.Exploited{KEV: map[string]snapshot.KEV{"CVE-2024-0002": {Added: "2026-11-01"}}})
}

func localSnapshotWith(t *testing.T, created time.Time, ex snapshot.Exploited) (string, string) {
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
		{ID: "GHSA-cccc", Summary: "No CVE", Affected: []osv.Affected{{
			Package: osv.Package{Ecosystem: "NuGet", Name: "NoCVE"},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
		}}},
	}
	files := map[string][]byte{
		"run/osv-NuGet.json.gz": gz(t, vulns),
		"run/exploited.json.gz": gz(t, ex),
	}
	idx := snapshot.Index{Format: snapshot.Format, Created: created, Expires: created.Add(snapshot.Validity)}
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

// liveCache pre-fills the EUVD and EPSS copies, so the test makes no requests. ENISA lists GHSA-cccc by its GHSA ID.
func liveCache(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	live := filepath.Join(cache, "live")
	os.MkdirAll(live, 0o755)
	os.WriteFile(filepath.Join(live, "euvd.json"), []byte(`{"GHSA-cccc":{"id":"EUVD-2026-3"}}`), 0o644)
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

func TestRunExploitedByAliasAndFeeds(t *testing.T) {
	dir, pub := localSnapshot(t)
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Type: cyclonedx.ComponentTypeLibrary, Name: "NoCVE", Version: "1.0.0", PackageURL: "pkg:nuget/NoCVE@1.0.0"},
	}}
	rep, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: liveCache(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].EUVD != "EUVD-2026-3" || !rep.Findings[0].Exploited() {
		t.Fatalf("findings = %+v; want GHSA-cccc marked exploited by its GHSA ID", rep.Findings)
	}
	if len(rep.Feeds) != 3 || !rep.Feeds[0].Used || !rep.Feeds[1].Used || !rep.Feeds[2].Used || rep.Feeds[1].AgeHours == nil {
		t.Errorf("feeds = %+v", rep.Feeds)
	}
	if missing := rep.MissingExploitedFeeds(); len(missing) != 0 {
		t.Errorf("missing = %q", missing)
	}
	if names := sourceNames(rep.Sources); len(rep.Sources) != 2 || names != snapshot.EUVDSource.Name+","+snapshot.EPSSSource.Name {
		t.Errorf("sources = %s", names)
	}
}

func TestRunWithoutEUVD(t *testing.T) {
	dir, pub := localSnapshot(t)
	cache := liveCache(t)
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Type: cyclonedx.ComponentTypeLibrary, Name: "NoCVE", Version: "1.0.0", PackageURL: "pkg:nuget/NoCVE@1.0.0"},
	}}
	// The first scan caches the snapshot (the feed copies are fresh, so no request). Then, offline, the EUVD copy is gone.
	if _, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: cache}); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(cache, "live", "euvd.json"))
	rep, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: cache, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if missing := rep.MissingExploitedFeeds(); len(missing) != 1 || missing[0] != FeedEUVD {
		t.Errorf("missing = %q", missing)
	}
	if rep.Findings[0].Exploited() {
		t.Error("exploited without a feed")
	}
	for _, s := range rep.Sources {
		if s.Name == snapshot.EUVDSource.Name {
			t.Error("EUVD listed as a source although it was not used")
		}
	}
	if !hasWarning(rep, "CISA KEV only") {
		t.Errorf("warnings = %q", rep.Warnings)
	}
}

func TestRunStaleData(t *testing.T) {
	created := time.Now().UTC().Add(-9 * 24 * time.Hour)
	dir, pub := localSnapshotAt(t, created)
	cache := liveCache(t)
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Lib", Version: "1.0.0", PackageURL: "pkg:nuget/Lib@1.0.0"},
	}}
	if _, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: cache, Offline: true}); err == nil {
		t.Fatal("offline without a cached snapshot should fail")
	}
	// Cache the snapshot while the feed copies are fresh (no request), then age the copies and scan offline.
	if _, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: cache}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-3 * 24 * time.Hour)
	for _, f := range []string{"euvd.json", "epss.csv.gz"} {
		os.Chtimes(filepath.Join(cache, "live", f), old, old)
	}
	rep, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: cache, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"snapshot is 9 days old", "snapshot expired on", "ENISA EUVD copy is 3 days old", "EPSS copy is 3 days old"} {
		if !hasWarning(rep, want) {
			t.Errorf("no warning %q in %q", want, rep.Warnings)
		}
	}
	if rep.SnapshotAgeHours < 9*24 || rep.SnapshotExpires.IsZero() {
		t.Errorf("age %v, expires %v", rep.SnapshotAgeHours, rep.SnapshotExpires)
	}
	if got := rep.OlderThan(48*time.Hour, time.Now()); len(got) != 3 {
		t.Errorf("older than 48h = %q", got)
	}
	if got := rep.OlderThan(30*24*time.Hour, time.Now()); len(got) != 0 {
		t.Errorf("older than 30 days = %q", got)
	}
}

func hasWarning(rep *Report, part string) bool {
	for _, w := range rep.Warnings {
		if strings.Contains(w, part) {
			return true
		}
	}
	return false
}

func sourceNames(list []snapshot.Source) string {
	var names []string
	for _, s := range list {
		names = append(names, s.Name)
	}
	return strings.Join(names, ",")
}

func TestRunEmptyKEV(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Other", Version: "1.0.0", PackageURL: "pkg:nuget/Other@1.0.0"},
	}}
	for _, kev := range []map[string]snapshot.KEV{{}, {"CVE-": {Added: "2026-11-01"}, "": {Added: "2026-11-01"}}} {
		dir, pub := localSnapshotWith(t, time.Now().UTC(), snapshot.Exploited{KEV: kev})
		rep, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: liveCache(t)})
		if err != nil {
			t.Fatal(err)
		}
		if missing := rep.MissingExploitedFeeds(); len(missing) != 1 || missing[0] != FeedKEV || !hasWarning(rep, "no usable CISA KEV list") {
			t.Errorf("KEV %v: missing %q, warnings %q", kev, missing, rep.Warnings)
		}
	}
}

func TestRunKEVWithoutDate(t *testing.T) {
	dir, pub := localSnapshotWith(t, time.Now().UTC(), snapshot.Exploited{KEV: map[string]snapshot.KEV{" CVE-2024-0002 ": {}}})
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Type: cyclonedx.ComponentTypeLibrary, Name: "Other", Version: "1.0.0", PackageURL: "pkg:nuget/Other@1.0.0"},
	}}
	rep, err := Run(context.Background(), Options{BOM: bom, Snapshot: dir, Keys: []string{pub}, CacheDir: liveCache(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].KEV != KEVNoDate || !rep.Findings[0].Exploited() || len(rep.MissingExploitedFeeds()) != 0 {
		t.Errorf("findings %+v, missing %q; want GHSA-bbbb exploited by its KEV entry without a date", rep.Findings, rep.MissingExploitedFeeds())
	}
}
