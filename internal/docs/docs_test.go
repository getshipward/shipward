package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getshipward/shipward/internal/config"
)

func load(t *testing.T, yaml string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shipward.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func read(t *testing.T, cfg *config.Config, rel string) string {
	t.Helper()
	b, err := os.ReadFile(cfg.Resolve(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWrite(t *testing.T) {
	cfg := load(t, `product:
  name: Example Game
  description: A board game.
  website: https://example.com/game
  support_until: "2031-12"
manufacturer:
  name: Example s.p.
  email: sec@example.com
security:
  languages: [en, sl]
`)
	now := time.Date(2026, 11, 6, 15, 0, 0, 0, time.UTC)
	results, err := Write(cfg, nil, false, now, "shipward test")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(All) {
		t.Fatalf("results = %+v", results)
	}
	for _, r := range results {
		if !r.Written {
			t.Errorf("%s not written", r.Path)
		}
	}

	txt := read(t, cfg, "cra/security.txt")
	for _, want := range []string{"Contact: mailto:sec@example.com", "Expires: 2027-10-06T00:00:00Z",
		"Preferred-Languages: en, sl", "Canonical: https://example.com/.well-known/security.txt"} {
		if !strings.Contains(txt, want) {
			t.Errorf("security.txt lacks %q:\n%s", want, txt)
		}
	}
	sec := read(t, cfg, "SECURITY.md")
	for _, want := range []string{"made by Example s.p.\n", "Reports in English or Slovenian", "until December 2031", "sec@example.com"} {
		if !strings.Contains(sec, want) {
			t.Errorf("SECURITY.md lacks %q", want)
		}
	}
	for _, unwanted := range []string{"5 working days", "30 days", "90 days", "please update to it.\n"} {
		if strings.Contains(sec, unwanted) {
			t.Errorf("SECURITY.md promises %q, which the maker did not choose", unwanted)
		}
	}
	if !strings.Contains(sec, "Article 13(10)") {
		t.Error("SECURITY.md does not name the conditions for updating only the latest version")
	}
	if strings.Contains(sec, "s.p..") {
		t.Error("double full stop")
	}
	doc := read(t, cfg, "cra/declaration-of-conformity.md")
	if !strings.HasPrefix(doc, "<!-- Draft written by shipward test on 2026-11-06.") || !strings.Contains(doc, "Regulation (EU) 2024/2847") ||
		!strings.Contains(doc, "**Product**: Example Game: A board game. TODO") || strings.Contains(doc, "..") {
		t.Errorf("declaration:\n%s", doc)
	}
	if strings.Contains(strings.ToLower(doc+sec+txt), "compliant") {
		t.Error("a draft says compliant")
	}

	// A second run keeps the files; --force writes them again; --only picks one.
	os.WriteFile(cfg.Resolve("SECURITY.md"), []byte("mine TODO\n"), 0o644)
	results, err = Write(cfg, []string{"security"}, false, now, "shipward test")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Written || results[0].TODOs != 1 || read(t, cfg, "SECURITY.md") != "mine TODO\n" {
		t.Errorf("kept: %+v", results)
	}
	if results, _ = Write(cfg, []string{"security"}, true, now, "shipward test"); !results[0].Written {
		t.Error("--force did not write")
	}
	if _, err := Write(cfg, []string{"nope"}, false, now, "shipward test"); err == nil {
		t.Error("unknown document accepted")
	}
}

func TestMissingValuesAreTODO(t *testing.T) {
	cfg := load(t, "product:\n  name: App\nmanufacturer:\n  name: Maker\n")
	results, err := Write(cfg, []string{"user-information", "security"}, false, time.Now(), "shipward test")
	if err != nil {
		t.Fatal(err)
	}
	info := read(t, cfg, "cra/user-information.md")
	for _, want := range []string{"TODO: postal address", "TODO: e-mail", "TODO: a security contact", "TODO: the end of the support period"} {
		if !strings.Contains(info, want) {
			t.Errorf("user information lacks %q", want)
		}
	}
	for _, r := range results {
		if r.TODOs == 0 {
			t.Errorf("%s: no TODOs counted", r.Path)
		}
	}
}

func TestSecurityTxtWithoutContact(t *testing.T) {
	cfg := load(t, "product:\n  name: App\nmanufacturer:\n  name: Maker\n")
	results, err := Write(cfg, []string{"security.txt"}, false, time.Date(2026, 3, 31, 9, 0, 0, 0, time.UTC), "shipward test")
	if err != nil {
		t.Fatal(err)
	}
	txt := read(t, cfg, "cra/security.txt")
	if strings.Contains(txt, "Contact: \n") || !strings.Contains(txt, "Contact: TODO") || results[0].TODOs != 1 {
		t.Errorf("TODOs = %d, security.txt:\n%s", results[0].TODOs, txt)
	}
	// 31 March + 11 months is 3 March of the next year (Go normalises 31 February): still less than a year.
	if !strings.Contains(txt, "Expires: 2027-03-03T00:00:00Z") {
		t.Errorf("Expires:\n%s", txt)
	}
	if w := Warnings(cfg); len(w) != 1 || !strings.Contains(w[0], "RFC 9116") {
		t.Errorf("Warnings = %q", w)
	}
}

func TestSecurityResponseTimes(t *testing.T) {
	cfg := load(t, `product:
  name: App
manufacturer:
  name: Maker
  email: s@example.com
security:
  acknowledge_working_days: 3
  assessment_days: 14
  disclosure_days: 60
`)
	if _, err := Write(cfg, []string{"security"}, false, time.Now(), "shipward test"); err != nil {
		t.Fatal(err)
	}
	sec := read(t, cfg, "SECURITY.md")
	for _, want := range []string{"within 3 working days.", "within 14 days whether", "or for 60 days, whichever"} {
		if !strings.Contains(sec, want) {
			t.Errorf("SECURITY.md lacks %q:\n%s", want, sec)
		}
	}
	if w := Warnings(cfg); len(w) != 0 {
		t.Errorf("Warnings = %q", w)
	}
}

func TestLanguageNames(t *testing.T) {
	for in, want := range map[string]string{"en": "English", "en,sl": "English or Slovenian", "en,de,xx": "English, German or xx"} {
		if got := languageNames(strings.Split(in, ",")); got != want {
			t.Errorf("languageNames(%s) = %q, want %q", in, got, want)
		}
	}
}
