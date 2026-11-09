package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getshipward/shipward/internal/config"
)

var cet = time.FixedZone("CET", 3600)

func TestDeadlines(t *testing.T) {
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	v := Case{Type: Vulnerability, Title: "x", Aware: aware}
	ds := v.Deadlines()
	if !ds[0].Due.Equal(aware.Add(24*time.Hour)) || !ds[1].Due.Equal(aware.Add(72*time.Hour)) || !ds[2].Due.IsZero() || !ds[3].Due.IsZero() {
		t.Fatalf("vulnerability before a fix: %+v", ds)
	}
	fix := aware.Add(48 * time.Hour)
	v.FixAvailable = &fix
	if got := v.Deadlines()[2].Due; !got.Equal(fix.Add(14 * 24 * time.Hour)) {
		t.Errorf("final after fix = %s", got)
	}

	inc := Case{Type: Incident, Title: "y", Aware: aware}
	if !inc.Deadlines()[2].Due.IsZero() {
		t.Error("incident final due before the notification is sent")
	}
	sent := aware.Add(70 * time.Hour)
	inc.Submitted = map[string]time.Time{EarlyWarning: aware.Add(time.Hour), Notification: sent}
	if got := inc.Deadlines()[2].Due; !got.Equal(sent.AddDate(0, 1, 0)) {
		t.Errorf("incident final = %s, want one month after the notification", got)
	}
	if next, ok := inc.Next(); !ok || next.Stage != Final {
		t.Errorf("next = %+v", next)
	}
}

func TestValidate(t *testing.T) {
	err := Case{Type: "breach", Malicious: "maybe", Submitted: map[string]time.Time{"later": {}}}.Validate()
	for _, want := range []string{`type "breach"`, "title is required", "aware is required", `malicious "maybe"`, `unknown stage "later"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
	}
}

func TestSaveLoadAndDrafts(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "cra.yaml")
	os.WriteFile(cfgPath, []byte("product:\n  name: Example Game\n  description: A board game.\n  markets: [EU]\nmanufacturer:\n  name: Example s.p.\n  email: sec@example.com\nreports:\n  csirt: SI-CERT\n"), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	c := &Case{Type: Incident, Title: "Update server hit", Aware: aware, Malicious: "yes", MemberStates: cfg.Product.Markets,
		MeasuresTaken: []string{"Took the server off line"}}
	id := Slug(aware, c.Title)
	if id != "2026-11-05-update-server-hit" {
		t.Errorf("slug = %q", id)
	}
	dir := filepath.Join(cfg.Resolve(cfg.Reports.Dir), id)
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || !got.Aware.Equal(aware) || got.Malicious != "yes" {
		t.Fatalf("load = %+v, %v", got, err)
	}
	if ids, _ := List(cfg.Resolve(cfg.Reports.Dir)); len(ids) != 1 || ids[0] != id {
		t.Errorf("list = %q", ids)
	}

	written, err := WriteDrafts(dir, id, got, cfg, false, cet, "cra test")
	if err != nil || len(written) != 4 {
		t.Fatalf("drafts = %q, %v", written, err)
	}
	early, _ := os.ReadFile(filepath.Join(dir, "early-warning.md"))
	for _, want := range []string{"Due Fri 6 Nov 2026 15:00 CET", "to SI-CERT", "All EU Member States",
		"Suspected to be caused by unlawful or malicious acts | yes", "14(4)(a)"} {
		if !strings.Contains(string(early), want) {
			t.Errorf("early warning lacks %q:\n%s", want, early)
		}
	}
	note, _ := os.ReadFile(filepath.Join(dir, "notification.md"))
	if !strings.Contains(string(note), "Initial assessment") || !strings.Contains(string(note), "- Took the server off line") ||
		!strings.Contains(string(note), "Example Game: A board game. Manufacturer") || strings.Contains(string(note), "..") {
		t.Errorf("notification:\n%s", note)
	}
	if info, _ := os.Stat(filepath.Join(dir, "users.md")); info.Mode().Perm() != 0o600 {
		t.Errorf("users.md mode %v; want private", info.Mode().Perm())
	}
	if again, _ := WriteDrafts(dir, id, got, cfg, false, cet, "cra test"); len(again) != 0 {
		t.Errorf("drafts overwritten without force: %q", again)
	}
}

func TestParseTime(t *testing.T) {
	if got, err := ParseTime("2026-11-06 14:00", cet); err != nil || !got.Equal(time.Date(2026, 11, 6, 14, 0, 0, 0, cet)) {
		t.Errorf("local form = %s, %v", got, err)
	}
	if _, err := ParseTime("yesterday", cet); err == nil {
		t.Error("accepted yesterday")
	}
}
