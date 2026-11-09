package snapshot

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/getshipward/shipward/internal/osv"
)

// maxIndex caps index.json; data files are capped by the size the signed index states.
const maxIndex = 1 << 20

// Client fetches a snapshot, checks it and keeps a copy in a cache folder, so later scans need only the index.
type Client struct {
	HTTP *http.Client
	// Base is the snapshot URL (ending in "/") or a local folder that holds index.json.
	Base      string
	CacheDir  string
	Keys      []string
	UserAgent string
	// Offline uses only the cached copy and makes no request.
	Offline bool
}

// Data is a loaded snapshot.
type Data struct {
	Index     Index
	Vulns     map[string][]osv.Vulnerability // by ecosystem
	Exploited Exploited
	// Warning is set when the scan uses an older copy (no network, or the server offered an older index).
	Warning string
}

// Load returns the snapshot with the OSV files of the given ecosystems.
func (c *Client) Load(ctx context.Context, ecosystems []string) (*Data, error) {
	d := &Data{Vulns: map[string][]osv.Vulnerability{}}
	idx, err := c.index(ctx, d)
	if err != nil {
		return nil, err
	}
	d.Index = idx

	want := map[string]bool{}
	for _, e := range ecosystems {
		want[e] = true
	}
	for _, f := range idx.Files {
		if f.Kind == "osv" && !want[f.Ecosystem] {
			continue
		}
		data, err := c.file(ctx, f)
		if err != nil {
			return nil, err
		}
		switch f.Kind {
		case "osv":
			var vulns []osv.Vulnerability
			if err := decodeGzipJSON(data, &vulns); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			d.Vulns[f.Ecosystem] = vulns
		case "exploited":
			if err := decodeGzipJSON(data, &d.Exploited); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
		}
	}
	c.prune(idx)
	return d, nil
}

// index fetches and checks index.json. A newer cached index wins (a server must not roll shipward back to older data), and
// without a network the cached one is used.
func (c *Client) index(ctx context.Context, d *Data) (Index, error) {
	cachePath := filepath.Join(c.CacheDir, "index.json")
	var cached *Index
	if data, err := os.ReadFile(cachePath); err == nil {
		if idx, err := Open(c.Keys, data); err == nil {
			cached = &idx
		}
	}

	if c.Offline {
		if cached == nil {
			return Index{}, errors.New("no cached vulnerability snapshot: run shipward scan once without --offline")
		}
		return *cached, nil
	}
	data, err := c.get(ctx, "index.json", maxIndex)
	if err != nil {
		if cached == nil {
			return Index{}, fmt.Errorf("vulnerability snapshot: %w", err)
		}
		d.Warning = fmt.Sprintf("could not fetch a new snapshot (%v); using the copy from %s", err, cached.Created.Format(time.DateOnly))
		return *cached, nil
	}
	idx, err := Open(c.Keys, data)
	if err != nil {
		return Index{}, err
	}
	if cached != nil && cached.Created.After(idx.Created) {
		d.Warning = fmt.Sprintf("the server offered an older snapshot (%s); using the copy from %s", idx.Created.Format(time.DateOnly), cached.Created.Format(time.DateOnly))
		return *cached, nil
	}
	if err := os.MkdirAll(c.CacheDir, 0o755); err == nil {
		_ = writeAtomic(cachePath, data)
	}
	return idx, nil
}

// file returns a data file from the cache, or downloads it. Either way its SHA-256 must match the signed index.
func (c *Client) file(ctx context.Context, f File) ([]byte, error) {
	if !validPath(f.Path) {
		return nil, fmt.Errorf("snapshot index names a bad path %q", f.Path)
	}
	local := filepath.Join(c.CacheDir, filepath.FromSlash(f.Path))
	if data, err := os.ReadFile(local); err == nil && sum(data) == f.SHA256 {
		return data, nil
	}
	if c.Offline {
		return nil, fmt.Errorf("%s is not cached: run shipward scan once without --offline", f.Path)
	}
	data, err := c.get(ctx, f.Path, f.Size)
	if err != nil {
		return nil, err
	}
	if sum(data) != f.SHA256 {
		return nil, fmt.Errorf("%s: SHA-256 does not match the signed index", f.Path)
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err == nil {
		_ = writeAtomic(local, data)
	}
	return data, nil
}

// prune removes cached run folders the index no longer names.
func (c *Client) prune(idx Index) {
	keep := map[string]bool{}
	for _, f := range idx.Files {
		keep[path.Dir(f.Path)] = true
	}
	entries, err := os.ReadDir(c.CacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && !keep[e.Name()] {
			_ = os.RemoveAll(filepath.Join(c.CacheDir, e.Name()))
		}
	}
}

// get reads a file below Base, at most limit bytes.
func (c *Client) get(ctx context.Context, rel string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(c.Base, "https://") && !strings.HasPrefix(c.Base, "http://") {
		f, err := os.Open(filepath.Join(c.Base, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readLimited(f, limit)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.Base, "/")+"/"+rel, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", req.URL, resp.Status)
	}
	return readLimited(resp.Body, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file is larger than the signed index says")
	}
	return data, nil
}

func validPath(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, "\\") && path.Clean(p) == p && !strings.HasPrefix(p, "..")
}

func sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func decodeGzipJSON(data []byte, v any) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	return json.NewDecoder(gz).Decode(v)
}

// DefaultCacheDir is the user's cache folder for shipward: snapshot/<source>/ and live/ below it.
func DefaultCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "shipward")
	}
	return filepath.Join(dir, "shipward")
}
