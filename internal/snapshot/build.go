package snapshot

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getshipward/shipward/internal/osv"
)

// Upstream addresses. EUVD and EPSS are not passed on in the snapshot (their reuse terms are unclear): shipward fetches
// them itself (live.go).
const (
	OSVBase = "https://osv-vulnerabilities.storage.googleapis.com/"
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// KEVMirrorURL is CISA's own copy of the catalog on GitHub (cisagov/kev-data). cisa.gov answers 403 to some data-centre
	// addresses (seen Nov 2026), GitHub does not.
	KEVMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	EUVDURL      = "https://euvdservices.enisa.europa.eu/api/search"
	EPSSURL      = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// DefaultEcosystems are the OSV ecosystems the snapshot carries.
var DefaultEcosystems = []string{"npm", "NuGet", "Packagist", "Go", "PyPI", "Maven", "crates.io", "RubyGems"}

// RecordSource is an OSV record source the snapshot may pass on, chosen by ID prefix. Records from any other source
// are dropped: their terms were not checked.
type RecordSource struct {
	Prefix string
	Source Source
}

// Builder makes one snapshot.
type Builder struct {
	HTTP       *http.Client
	Ecosystems []string
	Records    []RecordSource
	OSVBase    string
	// KEVURLs are tried in order; the first that answers wins.
	KEVURLs   []string
	UserAgent string
	Log       *slog.Logger
	Now       func() time.Time
	// Extra sources named in the index (KEV).
	FeedSources []Source
}

// Build writes a snapshot into dir: a new run folder with the data files, then index.json. It returns the paths it
// wrote, relative to dir, index.json last.
func (b *Builder) Build(ctx context.Context, dir string, key ed25519.PrivateKey) ([]string, error) {
	now := b.Now().UTC()
	run := now.Format("20060102T150405Z")
	if err := os.MkdirAll(filepath.Join(dir, run), 0o755); err != nil {
		return nil, err
	}
	idx := Index{Format: Format, Created: now}
	var written []string
	used := map[string]bool{}

	for _, eco := range b.Ecosystems {
		vulns, dropped, err := b.ecosystem(ctx, eco, used)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", eco, err)
		}
		rel := path.Join(run, FileName(eco))
		f, err := writeGzipJSON(filepath.Join(dir, rel), vulns)
		if err != nil {
			return nil, err
		}
		f.Kind, f.Ecosystem, f.Path, f.Records = "osv", eco, rel, len(vulns)
		idx.Files = append(idx.Files, f)
		written = append(written, rel)
		b.Log.Info("ecosystem", "ecosystem", eco, "records", len(vulns), "dropped", dropped, "bytes", f.Size)
	}

	ex, err := b.exploited(ctx)
	if err != nil {
		return nil, err
	}
	rel := path.Join(run, "exploited.json.gz")
	f, err := writeGzipJSON(filepath.Join(dir, rel), ex)
	if err != nil {
		return nil, err
	}
	f.Kind, f.Path, f.Records = "exploited", rel, len(ex.KEV)
	idx.Files = append(idx.Files, f)
	written = append(written, rel)
	b.Log.Info("exploited", "kev", len(ex.KEV))

	for _, r := range b.Records {
		if used[r.Prefix] {
			idx.Sources = append(idx.Sources, r.Source)
		}
	}
	idx.Sources = append(idx.Sources, b.FeedSources...)

	sealed, err := Seal(key, idx)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(dir, "index.json"), sealed); err != nil {
		return nil, err
	}
	return append(written, "index.json"), nil
}

// ecosystem reads OSV's all.zip of one ecosystem and keeps the records from allowed sources.
func (b *Builder) ecosystem(ctx context.Context, eco string, used map[string]bool) ([]osv.Vulnerability, int, error) {
	tmp, err := os.CreateTemp("", "osv-*.zip")
	if err != nil {
		return nil, 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := b.fetcher().download(ctx, b.OSVBase+url.PathEscape(eco)+"/all.zip", tmp); err != nil {
		return nil, 0, err
	}
	info, err := tmp.Stat()
	if err != nil {
		return nil, 0, err
	}
	zr, err := zip.NewReader(tmp, info.Size())
	if err != nil {
		return nil, 0, err
	}

	var out []osv.Vulnerability
	dropped := 0
	for _, zf := range zr.File {
		if !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		prefix := b.allowed(strings.TrimSuffix(path.Base(zf.Name), ".json"))
		if prefix == "" {
			dropped++
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, 0, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, 0, err
		}
		v, err := osv.Parse(data, eco)
		if err != nil {
			b.Log.Warn("skip record", "file", zf.Name, "err", err)
			continue
		}
		if v.Withdrawn != "" || len(v.Affected) == 0 {
			continue
		}
		used[prefix] = true
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, dropped, nil
}

func (b *Builder) allowed(id string) string {
	for _, r := range b.Records {
		if strings.HasPrefix(id, r.Prefix) {
			return r.Prefix
		}
	}
	return ""
}

func (b *Builder) exploited(ctx context.Context) (Exploited, error) {
	var errs []error
	for _, u := range b.KEVURLs {
		kev, err := b.fetcher().KEV(ctx, u)
		if err == nil {
			b.Log.Info("kev source", "url", u)
			return Exploited{KEV: kev}, nil
		}
		b.Log.Warn("kev source failed", "url", u, "err", err)
		errs = append(errs, err)
	}
	return Exploited{}, fmt.Errorf("KEV: %w", errors.Join(errs...))
}

func (b *Builder) fetcher() *Fetcher { return &Fetcher{HTTP: b.HTTP, UserAgent: b.UserAgent} }

// writeGzipJSON writes v as gzip-compressed JSON and returns the file's size and SHA-256.
func writeGzipJSON(p string, v any) (File, error) {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return File{}, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	counter := &countWriter{w: io.MultiWriter(tmp, h)}
	gz, err := gzip.NewWriterLevel(counter, gzip.BestCompression)
	if err != nil {
		tmp.Close()
		return File{}, err
	}
	if err := json.NewEncoder(gz).Encode(v); err != nil {
		tmp.Close()
		return File{}, err
	}
	if err := gz.Close(); err != nil {
		tmp.Close()
		return File{}, err
	}
	if err := tmp.Close(); err != nil {
		return File{}, err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return File{}, err
	}
	return File{SHA256: hex.EncodeToString(h.Sum(nil)), Size: counter.n}, nil
}

func writeAtomic(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
