// Package snapshot is the daily, signed copy of public vulnerability data that shipward scan matches against, on the
// maker's own machine. The builder (cmd/shipward-snapshot) publishes it; shipward downloads only the files it needs.
// Nobody sends package names anywhere: the files are the same for everyone.
//
// Layout under the base URL:
//
//	index.json       an Envelope: the Index (files, their SHA-256, the sources and their licences) and its Ed25519
//	                 signature in one object, so a reader never gets an index with another index's signature
//	<run>/osv-<ecosystem>.json.gz, <run>/exploited.json.gz
//
// Each run writes a new <run> folder and replaces index.json last, so a reader never sees an index that names missing
// files, and files a reader is still downloading are not overwritten.
package snapshot

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Format is the version of this layout. A shipward that does not know a format refuses the snapshot.
const Format = 1

// DefaultURL is where the published snapshot lives: one folder per format.
const DefaultURL = "https://data.shipward.dev/v1/"

// Index lists the files of one snapshot.
type Index struct {
	Format  int       `json:"format"`
	Created time.Time `json:"created"`
	// Expires is when the builder no longer stands behind this snapshot. A snapshot is made daily, so an expired one
	// means the builder stopped, or something holds new ones back. Older indexes have none (the zero time).
	Expires time.Time `json:"expires,omitzero"`
	Files   []File    `json:"files"`
	Sources []Source  `json:"sources"`
}

// Validity is how long after Created a snapshot expires.
const Validity = 7 * 24 * time.Hour

// File is one data file. Kind is "osv" (records of one ecosystem) or "exploited".
type File struct {
	Kind      string `json:"kind"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Records   int    `json:"records"`
}

// Source names where data came from and under which terms it is passed on.
type Source struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Licence string `json:"licence"`
	Note    string `json:"note,omitempty"`
}

// Exploited is the content of exploited.json.gz. KEV and EPSS are keyed by CVE ID, EUVD by every ID ENISA lists (its
// own, CVE, GHSA, ...). EUVD and EPSS are filled by shipward from the sources directly (Live), never from the snapshot.
type Exploited struct {
	KEV      map[string]KEV  `json:"kev"`
	EUVD     map[string]EUVD `json:"euvd,omitempty"`
	EPSS     map[string]EPSS `json:"epss,omitempty"`
	EPSSDate string          `json:"epss_date,omitempty"`
}

// KEV is an entry of CISA's Known Exploited Vulnerabilities catalog.
type KEV struct {
	Added      string `json:"added"`
	Due        string `json:"due,omitempty"`
	Ransomware string `json:"ransomware,omitempty"` // "Known" or "Unknown"
}

// EUVD is an entry of ENISA's list of exploited vulnerabilities.
type EUVD struct {
	ID             string `json:"id"`
	ExploitedSince string `json:"exploited_since,omitempty"`
}

// EPSS is FIRST's exploit prediction: the chance of exploitation in the next 30 days, and its percentile.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// FileName is the file-safe form of an ecosystem name ("GitHub Actions" -> "GitHub-Actions").
func FileName(ecosystem string) string {
	return "osv-" + strings.ReplaceAll(ecosystem, " ", "-") + ".json.gz"
}

// TrustedKeys are the public keys shipward accepts snapshots from (base64, Ed25519). A new key is added here one release
// before the builder switches to it.
var TrustedKeys = []string{
	"lEo2EB4n5NrYCg2b0HUxtz/GYEvW05AW9OOfrfncpYg=", // since 6 Nov 2026
}

// Envelope is the content of index.json: the index JSON exactly as signed, and the signature.
type Envelope struct {
	Index     []byte `json:"index"`     // JSON of an Index (base64 in the file)
	Signature []byte `json:"signature"` // Ed25519 over Index (base64 in the file)
}

// Seal signs an index.
func Seal(key ed25519.PrivateKey, idx Index) ([]byte, error) {
	raw, err := json.Marshal(idx)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(Envelope{Index: raw, Signature: ed25519.Sign(key, raw)}, "", "  ")
}

// ErrSignature means the index is not signed by a trusted key.
var ErrSignature = errors.New("snapshot signature does not match a trusted key")

// Open checks an index.json against the trusted keys and returns the index.
func Open(keys []string, data []byte) (Index, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Index{}, fmt.Errorf("snapshot index: %w", err)
	}
	trusted := false
	for _, k := range keys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, env.Index, env.Signature) {
			trusted = true
			break
		}
	}
	if !trusted {
		return Index{}, ErrSignature
	}
	var idx Index
	if err := json.Unmarshal(env.Index, &idx); err != nil {
		return Index{}, fmt.Errorf("snapshot index: %w", err)
	}
	if idx.Format != Format {
		return Index{}, fmt.Errorf("snapshot format %d is not supported by this shipward (it reads format %d): update shipward", idx.Format, Format)
	}
	return idx, nil
}

// PublicKey returns the base64 public key of a private key, for TrustedKeys.
func PublicKey(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

// ParseKey reads a private key given as the base64 of its 32-byte seed.
func ParseKey(s string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key must be the base64 of a 32-byte Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
