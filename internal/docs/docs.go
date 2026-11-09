// Package docs writes drafts of the documents the EU Cyber Resilience Act asks a manufacturer to have: the
// coordinated vulnerability disclosure policy (SECURITY.md), security.txt, the information for users (Annex II), the
// EU declaration of conformity (Annex V) and the technical documentation (Annex VII). It fills in what cra.yaml knows
// and marks the rest TODO. The drafts help a maker prepare; a person completes and checks them.
package docs

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/getshipward/shipward/internal/config"
)

//go:embed templates/*.tmpl
var templates embed.FS

// Doc is one document cra init can write.
type Doc struct {
	Name     string // short name for --only
	Template string
	Root     bool // in the repository root instead of docs.dir
	File     string
}

// All lists the documents in the order cra init writes them.
var All = []Doc{
	{Name: "security", Template: "SECURITY.md.tmpl", Root: true, File: "SECURITY.md"},
	{Name: "security.txt", Template: "security.txt.tmpl", File: "security.txt"},
	{Name: "user-information", Template: "user-information.md.tmpl", File: "user-information.md"},
	{Name: "declaration", Template: "declaration-of-conformity.md.tmpl", File: "declaration-of-conformity.md"},
	{Name: "technical-documentation", Template: "technical-documentation.md.tmpl", File: "technical-documentation.md"},
}

// data is what the templates see.
type data struct {
	Product      config.Product
	Manufacturer config.Manufacturer
	Security     config.Security
	SupportUntil string // "December 2031"
	Expires      string // security.txt: one year from today
	SBOM, VEX    string // paths relative to the repository
	Note         string
}

// Result says what happened to one document.
type Result struct {
	Path    string
	Written bool // false: it existed and was kept
	TODOs   int
}

// Write writes the documents (all, or the ones named in only) next to cra.yaml. An existing file is kept unless
// force is set.
func Write(cfg *config.Config, only []string, force bool, now time.Time, tool string) ([]Result, error) {
	d := data{
		Product:      cfg.Product,
		Manufacturer: cfg.Manufacturer,
		Security:     cfg.Security,
		Expires:      now.UTC().AddDate(1, 0, 0).Truncate(24 * time.Hour).Format(time.RFC3339),
		SBOM:         filepath.ToSlash(cfg.SBOM.Output),
		VEX:          filepath.ToSlash(cfg.VEX.Output),
		Note: fmt.Sprintf("Draft written by %s on %s. It helps you prepare; it is not legal advice and does not show "+
			"conformity. Fill in every TODO, check every sentence, then remove this note.", tool, now.Format(time.DateOnly)),
	}
	if cfg.Product.SupportUntil != "" {
		t, err := time.Parse("2006-01", cfg.Product.SupportUntil)
		if err != nil {
			return nil, err
		}
		d.SupportUntil = t.Format("January 2006")
	}

	want := map[string]bool{}
	for _, o := range only {
		want[o] = true
	}
	var unknown []string
	for o := range want {
		if !known(o) {
			unknown = append(unknown, o)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown document(s) %s (known: %s)", strings.Join(unknown, ", "), names())
	}

	funcs := template.FuncMap{
		"join": strings.Join,
		// sentence ends a sentence with a full stop, unless the text already ends with one ("..., s.p.").
		"sentence": func(s string) string {
			if strings.HasSuffix(s, ".") {
				return s
			}
			return s + "."
		},
		"languages": languageNames,
		// origin is scheme://host of a URL: security.txt lives at the root of the site, whatever path the website has.
		"origin": func(s string) string {
			u, err := url.Parse(s)
			if err != nil || u.Host == "" {
				return strings.TrimRight(s, "/")
			}
			return u.Scheme + "://" + u.Host
		},
		// contact shows the security contact as a person reads it: the address of a mailto: URI, or the URL.
		"contact": func(s string) string {
			if s == "" {
				return "TODO: a security contact (`security.contact` in cra.yaml)"
			}
			return strings.TrimPrefix(s, "mailto:")
		},
	}
	var results []Result
	for _, doc := range All {
		if len(want) > 0 && !want[doc.Name] {
			continue
		}
		path := cfg.Resolve(filepath.Join(cfg.Docs.Dir, doc.File))
		if doc.Root {
			path = cfg.Resolve(doc.File)
		}
		if _, err := os.Stat(path); err == nil && !force {
			results = append(results, Result{Path: path, TODOs: countTODOs(path)})
			continue
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return results, err
		}
		tmpl, err := template.New(doc.Template).Funcs(funcs).Option("missingkey=error").ParseFS(templates, "templates/"+doc.Template)
		if err != nil {
			return results, err
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, d); err != nil {
			return results, fmt.Errorf("%s: %w", doc.File, err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return results, err
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			return results, err
		}
		results = append(results, Result{Path: path, Written: true, TODOs: todos(buf.String())})
	}
	return results, nil
}

func countTODOs(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return todos(string(b))
}

// todos counts the TODO marks after the first line (the draft note, which mentions them).
func todos(s string) int {
	if i := strings.IndexByte(s, '\n'); i >= 0 && strings.Contains(s[:i], "Draft written by") {
		s = s[i+1:]
	}
	return strings.Count(s, "TODO")
}

func known(name string) bool {
	for _, d := range All {
		if d.Name == name {
			return true
		}
	}
	return false
}

func names() string {
	var n []string
	for _, d := range All {
		n = append(n, d.Name)
	}
	return strings.Join(n, ", ")
}

// languageNames writes language codes as names for people ("en, sl" -> "English or Slovenian").
func languageNames(codes []string) string {
	names := map[string]string{"en": "English", "sl": "Slovenian", "de": "German", "fr": "French", "it": "Italian",
		"es": "Spanish", "hr": "Croatian", "nl": "Dutch", "pl": "Polish", "pt": "Portuguese", "cs": "Czech", "hu": "Hungarian"}
	var out []string
	for _, c := range codes {
		if n, ok := names[strings.ToLower(c)]; ok {
			out = append(out, n)
		} else {
			out = append(out, c)
		}
	}
	if len(out) <= 1 {
		return strings.Join(out, "")
	}
	return strings.Join(out[:len(out)-1], ", ") + " or " + out[len(out)-1]
}
