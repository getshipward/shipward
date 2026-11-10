package main

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

	"github.com/getshipward/shipward/internal/osv"
	"github.com/getshipward/shipward/internal/snapshot"
)

// scanProject writes a project with two NuGet components, a signed local snapshot with an advisory on each (GHSA-bbbb on
// CISA's list, GHSA-dddd on no list), and fresh EUVD and EPSS copies in the cache, so no test makes a request. It returns the project folder,
// the snapshot folder and the key.
func scanProject(t *testing.T) (dir, snap, key string) {
	t.Helper()
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache) // macOS: os.UserCacheDir uses $HOME/Library/Caches
	ucd, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(ucd, "shipward", "live")
	gzipped := func(data []byte) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(data)
		w.Close()
		return buf.Bytes()
	}
	dir = t.TempDir()
	writeFiles(t, dir, map[string]string{
		"shipward.yaml": "product:\n  name: App\nmanufacturer:\n  name: Maker\n",
		"sbom/sbom.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
			{"type":"library","name":"Other","version":"1.0.0","purl":"pkg:nuget/Other@1.0.0"},
			{"type":"library","name":"Plain","version":"1.0.0","purl":"pkg:nuget/Plain@1.0.0"}]}`,
	})
	writeFiles(t, live, map[string]string{"euvd.json": `{"CVE-1999-0001":{"id":"EUVD-1999-1"}}`, "epss.csv.gz": string(gzipped([]byte("cve,epss,percentile\n")))})

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap = t.TempDir()
	toGzipJSON := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return gzipped(data)
	}
	files := []struct {
		kind, eco, path string
		data            []byte
	}{
		{"osv", "NuGet", "run/osv-NuGet.json.gz", toGzipJSON([]osv.Vulnerability{{ID: "GHSA-bbbb", Aliases: []string{"CVE-2024-0002"},
			Affected: []osv.Affected{{Package: osv.Package{Ecosystem: "NuGet", Name: "Other"},
				Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "9.0.0"}}}}}}},
			{ID: "GHSA-dddd", Affected: []osv.Affected{{Package: osv.Package{Ecosystem: "NuGet", Name: "Plain"},
				Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}}}})},
		{"exploited", "", "run/exploited.json.gz", toGzipJSON(snapshot.Exploited{KEV: map[string]snapshot.KEV{"CVE-2024-0002": {Added: "2026-11-01"}}})},
	}
	now := time.Now().UTC()
	idx := snapshot.Index{Format: snapshot.Format, Created: now, Expires: now.Add(snapshot.Validity)}
	for _, f := range files {
		writeFiles(t, snap, map[string]string{f.path: string(f.data)})
		h := sha256.Sum256(f.data)
		idx.Files = append(idx.Files, snapshot.File{Kind: f.kind, Ecosystem: f.eco, Path: f.path, SHA256: hex.EncodeToString(h[:]), Size: int64(len(f.data))})
	}
	sealed, err := snapshot.Seal(priv, idx)
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, snap, map[string]string{"index.json": string(sealed)})
	return dir, snap, snapshot.PublicKey(priv)
}

func TestScanExploitedHint(t *testing.T) {
	dir, snap, key := scanProject(t)
	cfg := filepath.Join(dir, "shipward.yaml")
	var stdout, stderr bytes.Buffer
	code := runScan(context.Background(), []string{"--config", cfg, "--snapshot", snap, "--trust-key", key, "--fail-on", "exploited"}, &stdout, &stderr)
	if code != exitFindings {
		t.Fatalf("exit %d, want %d: %s", code, exitFindings, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"EXPLOITED (CISA KEV since 2026-11-01)",
		"That alone is not a case to report",
		"CRA Art. 3(42), 14(1)",
		"shipward report new vulnerability --title 'GHSA-bbbb in Other@1.0.0' --advisory GHSA-bbbb --component pkg:nuget/Other@1.0.0",
		"Exploitation data: CISA KEV (in the snapshot), ENISA EUVD (fetched ",
		"(0 min old)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// Decided: no hint.
	writeFiles(t, dir, map[string]string{"vex.yaml": "- id: GHSA-bbbb\n  component: pkg:nuget/Other@1.0.0\n  status: not_affected\n  justification: component_not_present\n  date: \"2026-11-10\"\n"})
	stdout.Reset()
	if code := runScan(context.Background(), []string{"--config", cfg, "--snapshot", snap, "--trust-key", key, "--fail-on", "exploited"}, &stdout, &stderr); code != 0 {
		t.Fatalf("decided: exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "report new") {
		t.Errorf("hint for a decided advisory:\n%s", stdout.String())
	}
}

func TestScanFailOnExploitedWithoutEUVD(t *testing.T) {
	dir, snap, key := scanProject(t)
	cfg := filepath.Join(dir, "shipward.yaml")
	args := []string{"--config", cfg, "--snapshot", snap, "--trust-key", key}
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), args, &stdout, &stderr); code != 0 { // caches the snapshot
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	ucd, _ := os.UserCacheDir()
	os.Remove(filepath.Join(ucd, "shipward", "live", "euvd.json"))

	stdout.Reset()
	stderr.Reset()
	code := runScan(context.Background(), append(args, "--offline", "--fail-on", "exploited", "--format", "json"), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "ENISA EUVD could not be loaded") {
		t.Fatalf("exit %d, stderr %q; want 1 and the missing feed", code, stderr.String())
	}
	var rep struct {
		Feeds []struct {
			Name string `json:"name"`
			Used bool   `json:"used"`
		} `json:"feeds"`
		Sources []struct {
			Name string `json:"name"`
		} `json:"sources"`
		Age *float64 `json:"snapshot_age_hours"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Feeds) != 3 || rep.Feeds[1].Name != "ENISA EUVD" || rep.Feeds[1].Used || rep.Age == nil {
		t.Errorf("json feeds = %+v, age %v", rep.Feeds, rep.Age)
	}
	for _, s := range rep.Sources {
		if strings.Contains(s.Name, "ENISA") {
			t.Errorf("ENISA listed as a source: %+v", rep.Sources)
		}
	}

	// --fail-on open does not need the exploited lists.
	stderr.Reset()
	if code := runScan(context.Background(), append(args, "--offline", "--fail-on", "open"), &stdout, &stderr); code != exitFindings {
		t.Errorf("--fail-on open: exit %d: %s", code, stderr.String())
	}
}

func TestScanMaxAge(t *testing.T) {
	dir, snap, key := scanProject(t)
	args := []string{"--config", filepath.Join(dir, "shipward.yaml"), "--snapshot", snap, "--trust-key", key}
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), append(args, "--max-age", "1d"), &stdout, &stderr); code != 0 {
		t.Fatalf("fresh data: exit %d: %s", code, stderr.String())
	}
	ucd, _ := os.UserCacheDir()
	old := time.Now().Add(-50 * time.Hour)
	os.Chtimes(filepath.Join(ucd, "shipward", "live", "euvd.json"), old, old)
	stdout.Reset()
	if code := runScan(context.Background(), append(args, "--offline", "--max-age", "36h"), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "ENISA EUVD copy is 2 days old") {
		t.Errorf("old feed: exit %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "warning: the ENISA EUVD copy is 2 days old") {
		t.Errorf("no warning for the old copy:\n%s", stdout.String())
	}
	if code := runScan(context.Background(), append(args, "--max-age", "soon"), &stdout, &stderr); code != 2 {
		t.Errorf("bad --max-age: exit %d", code)
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"36h": 36 * time.Hour, "3d": 72 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseAge(in); err != nil || got != want {
			t.Errorf("parseAge(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "-1h", "xd", "0d", "3 days"} {
		if _, err := parseAge(in); err == nil {
			t.Errorf("parseAge(%q) accepted", in)
		}
	}
}

func TestTriageSetAffectedHint(t *testing.T) {
	dir, snap, key := scanProject(t)
	cfg := filepath.Join(dir, "shipward.yaml")
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"--config", cfg, "--snapshot", snap, "--trust-key", key}, &stdout, &stderr); code != 0 {
		t.Fatalf("scan: exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	args := []string{"set", "CVE-2024-0002", "pkg:nuget/Other@1.0.0", "--status", "affected", "--action", "Update to 9.0.0.",
		"--by", "alex", "--config", cfg, "--snapshot", snap, "--trust-key", key}
	if code := runTriage(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "recorded affected") || !strings.Contains(out, "--advisory GHSA-bbbb --component pkg:nuget/Other@1.0.0") {
		t.Errorf("stdout = %s", out)
	}

	// Both lists checked, neither names GHSA-dddd: nothing more to say.
	stdout.Reset()
	plain := []string{"set", "GHSA-dddd", "pkg:nuget/Plain@1.0.0", "--status", "affected", "--action", "Update to 2.0.0.",
		"--by", "alex", "--config", cfg, "--snapshot", snap, "--trust-key", key}
	if code := runTriage(context.Background(), plain, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); strings.Contains(out, "exploited") {
		t.Errorf("not exploited, both lists loaded: stdout = %s", out)
	}

	// ENISA's list missing: the lookup is not conclusive, and says so.
	ucd, _ := os.UserCacheDir()
	os.Remove(filepath.Join(ucd, "shipward", "live", "euvd.json"))
	stdout.Reset()
	if code := runTriage(context.Background(), plain, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "Could not check whether GHSA-dddd is known to be exploited (ENISA EUVD could not be loaded)") ||
		!strings.Contains(out, "shipward report new vulnerability --title 'GHSA-dddd in pkg:nuget/Plain@1.0.0' --advisory GHSA-dddd --component pkg:nuget/Plain@1.0.0") {
		t.Errorf("stdout = %s", out)
	}

	// An advisory the cached snapshot does not have for this component.
	stdout.Reset()
	other := append([]string{"set", "GHSA-zzzz", "pkg:nuget/Plain@1.0.0"}, plain[3:]...)
	if code := runTriage(context.Background(), other, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "the cached snapshot has no advisory GHSA-zzzz") {
		t.Errorf("stdout = %s", out)
	}

	// Without a cached snapshot it cannot tell, and says so.
	stdout.Reset()
	args[len(args)-3] = t.TempDir()
	if code := runTriage(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "Could not check whether CVE-2024-0002 is known to be exploited") {
		t.Errorf("stdout = %s", out)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"GHSA-bbbb":                "GHSA-bbbb",
		"pkg:npm/%40scope/a@1.0.0": "pkg:npm/%40scope/a@1.0.0",
		"GHSA-x in a@1":            "'GHSA-x in a@1'",
		"it's":                     `'it'\''s'`,
		"pkg:npm/a@1;rm -rf ~":     "'pkg:npm/a@1;rm -rf ~'",
		"$(id)":                    "'$(id)'",
		"":                         "''",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
