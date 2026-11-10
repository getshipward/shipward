package snapshot

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func upstream(t *testing.T) *httptest.Server {
	t.Helper()
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	records := map[string]string{
		"GHSA-aaaa.json": `{"id":"GHSA-aaaa","aliases":["CVE-2024-0001"],"affected":[{"package":{"ecosystem":"NuGet","name":"Lib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
		"GHSA-gone.json": `{"id":"GHSA-gone","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"NuGet","name":"Lib"}}]}`,
		"CGA-xxxx.json":  `{"id":"CGA-xxxx","affected":[{"package":{"ecosystem":"NuGet","name":"Lib"}}]}`,
	}
	for name, body := range records {
		w, _ := zw.Create(name)
		io.WriteString(w, body)
	}
	zw.Close()

	var epss bytes.Buffer
	gz := gzip.NewWriter(&epss)
	io.WriteString(gz, "#model_version:v2025.03.14,score_date:2026-11-06T12:55:00Z\ncve,epss,percentile\nCVE-2024-0001,0.5,0.99\nCVE-2024-9999,0.1,0.5\n")
	gz.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/osv/NuGet/all.zip", func(w http.ResponseWriter, r *http.Request) { w.Write(zipBuf.Bytes()) })
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2024-0001","dateAdded":"2026-11-01","dueDate":"2026-11-22","knownRansomwareCampaignUse":"Unknown"}]}`)
	})
	mux.HandleFunc("/euvd", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"total":1,"items":[{"id":"EUVD-2024-1","aliases":"GHSA-aaaa\nCVE-2024-0001\n","exploitedSince":"Nov 4, 2026, 12:00:00 AM"}]}`)
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) { w.Write(epss.Bytes()) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func build(t *testing.T, srv *httptest.Server, dir string, key ed25519.PrivateKey, now time.Time) {
	t.Helper()
	b := &Builder{
		HTTP:       srv.Client(),
		Ecosystems: []string{"NuGet"},
		Records:    []RecordSource{{Prefix: "GHSA-", Source: Source{Name: "GHSA", Licence: "CC-BY-4.0"}}},
		OSVBase:    srv.URL + "/osv/",
		KEVURLs:    []string{srv.URL + "/blocked", srv.URL + "/kev"}, // the first answers 404: the mirror is used
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        func() time.Time { return now },
	}
	files, err := b.Build(context.Background(), dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if files[len(files)-1] != "index.json" {
		t.Fatalf("index.json is not written last: %q", files)
	}
}

func newKey(t *testing.T) (ed25519.PrivateKey, []string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, []string{PublicKey(priv)}
}

func TestBuildAndLoad(t *testing.T) {
	srv := upstream(t)
	key, trusted := newKey(t)
	dir := t.TempDir()
	build(t, srv, dir, key, time.Date(2026, 11, 6, 3, 0, 0, 0, time.UTC))

	c := &Client{Base: dir, CacheDir: t.TempDir(), Keys: trusted}
	d, err := c.Load(context.Background(), []string{"NuGet"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Vulns["NuGet"]; len(got) != 1 || got[0].ID != "GHSA-aaaa" {
		t.Errorf("records = %+v; want only GHSA-aaaa (withdrawn and unlisted sources dropped)", got)
	}
	if ex := d.Exploited; ex.KEV["CVE-2024-0001"].Added != "2026-11-01" || ex.EUVD != nil || ex.EPSS != nil {
		t.Errorf("exploited = %+v; want KEV only (EUVD and EPSS are not passed on)", ex)
	}
	if want := d.Index.Created.Add(Validity); !d.Index.Expires.Equal(want) {
		t.Errorf("expires = %s, want %s", d.Index.Expires, want)
	}
	if len(d.Index.Sources) != 1 || d.Index.Sources[0].Name != "GHSA" {
		t.Errorf("sources = %+v", d.Index.Sources)
	}

	// Another key is refused.
	_, other := newKey(t)
	if _, err := (&Client{Base: dir, CacheDir: t.TempDir(), Keys: other}).Load(context.Background(), nil); !errors.Is(err, ErrSignature) {
		t.Errorf("other key: err = %v", err)
	}

	// A changed data file is refused.
	for _, f := range d.Index.Files {
		if f.Kind == "osv" {
			os.WriteFile(filepath.Join(dir, f.Path), []byte("changed"), 0o644)
		}
	}
	if _, err := (&Client{Base: dir, CacheDir: t.TempDir(), Keys: trusted}).Load(context.Background(), []string{"NuGet"}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("changed file: err = %v", err)
	}
}

func TestClientKeepsNewerCopy(t *testing.T) {
	srv := upstream(t)
	key, trusted := newKey(t)
	cache := t.TempDir()
	newer, older := t.TempDir(), t.TempDir()
	build(t, srv, newer, key, time.Date(2026, 11, 6, 3, 0, 0, 0, time.UTC))
	build(t, srv, older, key, time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC))

	if _, err := (&Client{Base: newer, CacheDir: cache, Keys: trusted}).Load(context.Background(), []string{"NuGet"}); err != nil {
		t.Fatal(err)
	}
	d, err := (&Client{Base: older, CacheDir: cache, Keys: trusted}).Load(context.Background(), []string{"NuGet"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Index.Created.Day() != 6 || !strings.Contains(d.Warning, "older snapshot") {
		t.Errorf("created %s, warning %q; want the newer cached copy", d.Index.Created, d.Warning)
	}

	// Without a network the cached copy is used, with a warning.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusBadGateway) }))
	defer down.Close()
	d, err = (&Client{HTTP: down.Client(), Base: down.URL + "/", CacheDir: cache, Keys: trusted}).Load(context.Background(), []string{"NuGet"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Warning, "could not fetch") || len(d.Vulns["NuGet"]) != 1 {
		t.Errorf("offline: warning %q, %d records", d.Warning, len(d.Vulns["NuGet"]))
	}
}

func TestOpenRejectsOtherFormat(t *testing.T) {
	key, trusted := newKey(t)
	sealed, err := Seal(key, Index{Format: Format + 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(trusted, sealed); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("format %d", Format+1)) {
		t.Errorf("err = %v", err)
	}
}

func TestValidPath(t *testing.T) {
	for p, want := range map[string]bool{"20261106T030000Z/osv-NuGet.json.gz": true, "../x": false, "/etc/passwd": false, "a/../../b": false, "": false} {
		if got := validPath(p); got != want {
			t.Errorf("validPath(%q) = %v", p, got)
		}
	}
}

func TestLive(t *testing.T) {
	srv := upstream(t)
	requests := 0
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		resp, err := srv.Client().Get(srv.URL + r.URL.String())
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}))
	defer counting.Close()

	now := time.Now()
	l := &Live{
		Fetcher:  &Fetcher{HTTP: counting.Client()},
		CacheDir: t.TempDir(),
		EUVDURL:  counting.URL + "/euvd",
		EPSSURL:  counting.URL + "/epss",
		MaxAge:   20 * time.Hour,
		Now:      func() time.Time { return now },
	}
	cves := map[string]bool{"CVE-2024-0001": true}
	d := l.Load(context.Background(), cves)
	if len(d.Warnings) != 0 || d.EUVD["CVE-2024-0001"].ExploitedSince != "2026-11-04" || d.EPSS["CVE-2024-0001"].Score != 0.5 || d.EPSSDate != "2026-11-06T12:55:00Z" {
		t.Fatalf("live = %+v", d)
	}
	// ENISA's own ID and every alias find the entry, not only the CVE.
	for _, id := range []string{"EUVD-2024-1", "GHSA-aaaa"} {
		if d.EUVD[id].ID != "EUVD-2024-1" {
			t.Errorf("EUVD[%s] = %+v", id, d.EUVD[id])
		}
	}
	if !d.EUVDFetched.Equal(now) || !d.EPSSFetched.Equal(now) {
		t.Errorf("fetched %s, %s; want %s", d.EUVDFetched, d.EPSSFetched, now)
	}
	if _, ok := d.EPSS["CVE-2024-9999"]; ok {
		t.Error("EPSS keeps a CVE nobody asked for")
	}
	first := requests
	l.Now = func() time.Time { return now.Add(time.Hour) }
	if d := l.Load(context.Background(), cves); d.EUVDFetched.After(now.Add(time.Minute)) {
		t.Errorf("cached copy: fetched %s; want the time of the first fetch", d.EUVDFetched)
	}
	if requests != first {
		t.Errorf("second load made %d requests; want the cached copies", requests-first)
	}

	offline := &Live{CacheDir: t.TempDir(), Offline: true, Now: time.Now}
	if d := offline.Load(context.Background(), cves); len(d.Warnings) != 2 || d.EUVD != nil || d.EPSS != nil {
		t.Errorf("offline without cache = %+v", d)
	}
}

func TestEmptyListsAreRefused(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"vulnerabilities":[]}`) })
	mux.HandleFunc("/kev-empty", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	mux.HandleFunc("/euvd", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"total":0,"items":[]}`) })
	mux.HandleFunc("/euvd-noid", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"total":1,"items":[{"id":"","aliases":"CVE-2024-0001"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f := &Fetcher{HTTP: srv.Client()}
	for _, u := range []string{"/kev", "/kev-empty"} {
		if _, err := f.KEV(context.Background(), srv.URL+u); err == nil {
			t.Errorf("KEV %s: accepted", u)
		}
	}
	for _, u := range []string{"/euvd", "/euvd-noid"} {
		if _, err := f.EUVD(context.Background(), srv.URL+u); err == nil {
			t.Errorf("EUVD %s: accepted", u)
		}
	}

	now := time.Now()
	cves := map[string]bool{}
	live := func(cache string, offline bool) *Live {
		return &Live{Fetcher: f, CacheDir: cache, EUVDURL: srv.URL + "/euvd", EPSSURL: srv.URL + "/none", MaxAge: 20 * time.Hour,
			Now: func() time.Time { return now }, Offline: offline}
	}

	// An empty cached copy is not used, online or offline.
	cache := t.TempDir()
	os.WriteFile(filepath.Join(cache, "euvd.json"), []byte(`{}`), 0o644)
	for _, offline := range []bool{false, true} {
		if d := live(cache, offline).Load(context.Background(), cves); d.EUVD != nil {
			t.Errorf("offline=%v: empty cached EUVD used: %+v", offline, d)
		}
	}

	// An older good copy wins over an empty answer, with a warning, and stays in the cache.
	good := `{"CVE-2024-0001":{"id":"EUVD-2024-1"}}`
	os.WriteFile(filepath.Join(cache, "euvd.json"), []byte(good), 0o644)
	old := now.Add(-30 * time.Hour)
	os.Chtimes(filepath.Join(cache, "euvd.json"), old, old)
	d := live(cache, false).Load(context.Background(), cves)
	if d.EUVD["CVE-2024-0001"].ID != "EUVD-2024-1" || !d.EUVDFetched.Equal(old) || !strings.Contains(strings.Join(d.Warnings, "\n"), "using an older one") {
		t.Errorf("older copy: %+v", d)
	}
	if data, _ := os.ReadFile(filepath.Join(cache, "euvd.json")); string(data) != good {
		t.Errorf("cache overwritten with %s", data)
	}
}
