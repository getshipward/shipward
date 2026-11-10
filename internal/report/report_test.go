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

	early := aware.AddDate(0, 0, -30)
	v.FixAvailable = &early
	if got := v.Deadlines()[2]; !got.Due.Equal(aware.Add(72*time.Hour)) || got.Hint == "" {
		t.Errorf("final with a fix long before awareness = %+v, want the notification's deadline and a hint", got)
	}
	shortly := aware.AddDate(0, 0, -5)
	v.FixAvailable = &shortly
	if got := v.Deadlines()[2]; !got.Due.Equal(shortly.Add(14*24*time.Hour)) || got.Hint != "" {
		t.Errorf("final with a fix 5 days before awareness = %+v", got)
	}

	inc := Case{Type: Incident, Title: "y", Aware: aware}
	if got := inc.Deadlines()[2]; !got.Latest || !got.Due.Equal(time.Date(2026, 12, 8, 15, 0, 0, 0, cet)) {
		t.Errorf("incident final before the notification is recorded = %+v, want at the latest aware + 72 h + 1 month", got)
	}
	sent := aware.Add(70 * time.Hour)
	inc.Submitted = map[string]time.Time{EarlyWarning: aware.Add(time.Hour), Notification: sent}
	if got := inc.Deadlines()[2]; got.Latest || !got.Due.Equal(time.Date(2026, 12, 8, 13, 0, 0, 0, cet)) {
		t.Errorf("incident final = %+v, want one month after the notification", got)
	}
	if next, ok := inc.Next(); !ok || next.Stage != Final {
		t.Errorf("next = %+v", next)
	}

	// At a month end the final report is due on the last day of the next month, not in the month after it.
	inc.Aware = time.Date(2026, 1, 29, 9, 0, 0, 0, cet)
	inc.Submitted = map[string]time.Time{EarlyWarning: inc.Aware, Notification: time.Date(2026, 1, 31, 10, 0, 0, 0, cet)}
	if got := inc.Deadlines()[2].Due; !got.Equal(time.Date(2026, 2, 28, 10, 0, 0, 0, cet)) {
		t.Errorf("incident final after a notification on 31 Jan = %s, want 28 Feb", got)
	}
}

func TestAddMonth(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2026-01-29", "2026-02-28"},
		{"2026-01-30", "2026-02-28"},
		{"2026-01-31", "2026-02-28"},
		{"2028-01-29", "2028-02-29"}, // leap year
		{"2028-01-30", "2028-02-29"},
		{"2028-01-31", "2028-02-29"},
		{"2026-03-31", "2026-04-30"},
		{"2026-05-31", "2026-06-30"},
		{"2026-12-31", "2027-01-31"},
		{"2026-11-05", "2026-12-05"},
		{"2026-02-28", "2026-03-28"},
	} {
		in, _ := time.ParseInLocation("2006-01-02 15:04", tc.in+" 10:30", cet)
		want, _ := time.ParseInLocation("2006-01-02 15:04", tc.want+" 10:30", cet)
		if got := AddMonth(in); !got.Equal(want) {
			t.Errorf("AddMonth(%s) = %s, want %s", tc.in, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	err := Case{Type: "breach", Malicious: "maybe", Submitted: map[string]time.Time{"later": {}}}.Validate()
	for _, want := range []string{`type "breach"`, "title is required", "aware is required", `malicious "maybe"`, `unknown stage "later"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
	}

	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	fix := aware.Add(time.Hour)
	err = Case{Type: Incident, Title: "x", Aware: aware, FixAvailable: &fix, Submitted: map[string]time.Time{
		EarlyWarning: aware.Add(-time.Hour), Final: aware.Add(time.Hour), Users: aware.Add(-time.Minute)}}.Validate()
	for _, want := range []string{"fix_available is for a vulnerability", "early-warning is before aware",
		"users is before aware", "final is recorded, notification is not"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
	}
	err = Case{Type: Vulnerability, Title: "x", Aware: aware, Submitted: map[string]time.Time{
		EarlyWarning: aware.Add(2 * time.Hour), Notification: aware.Add(time.Hour)}}.Validate()
	if err == nil || !strings.Contains(err.Error(), "notification is before early-warning") {
		t.Errorf("out of order: %v", err)
	}
	// Sent together, and the users' notice at any time after awareness: fine.
	early := aware.Add(-48 * time.Hour)
	if err := (Case{Type: Vulnerability, Title: "x", Aware: aware, FixAvailable: &early, Submitted: map[string]time.Time{
		EarlyWarning: aware.Add(time.Hour), Notification: aware.Add(time.Hour), Users: aware}}).Validate(); err != nil {
		t.Errorf("valid case: %v", err)
	}
}

func TestLoadLocalTimes(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "report.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The same forms the command line takes: without an offset they are local time, not UTC.
	write("type: vulnerability\ntitle: x\naware: 2026-03-01 10:00:00\nfix_available: \"2026-03-02 09:00\"\n" +
		"submitted:\n  early-warning: 2026-03-01T12:00:00+01:00\n  notification: 2026-03-01T13:00\n")
	c, err := Load(dir, cet)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Aware.Equal(time.Date(2026, 3, 1, 10, 0, 0, 0, cet)) || !c.FixAvailable.Equal(time.Date(2026, 3, 2, 9, 0, 0, 0, cet)) ||
		!c.Submitted[EarlyWarning].Equal(time.Date(2026, 3, 1, 12, 0, 0, 0, cet)) ||
		!c.Submitted[Notification].Equal(time.Date(2026, 3, 1, 13, 0, 0, 0, cet)) {
		t.Errorf("times = %s %s %v", c.Aware, c.FixAvailable, c.Submitted)
	}
	// Save writes the offset, so the file reads the same everywhere.
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	if again, err := Load(dir, time.UTC); err != nil || !again.Aware.Equal(c.Aware) {
		t.Errorf("after save = %+v, %v", again, err)
	}

	write("type: vulnerability\ntitle: x\naware: 2026-03-01\n")
	if _, err := Load(dir, cet); err == nil || !strings.Contains(err.Error(), "aware") {
		t.Errorf("date without a time: %v", err)
	}
	write("type: incident\ntitle: x\naware: 2026-03-01 10:00\nsubmitted:\n  notification: soon\n")
	if _, err := Load(dir, cet); err == nil || !strings.Contains(err.Error(), "submitted: notification") {
		t.Errorf("bad submitted time: %v", err)
	}
}

func TestSaveLoadAndDrafts(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "shipward.yaml")
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
	got, err := Load(dir, cet)
	if err != nil || !got.Aware.Equal(aware) || got.Malicious != "yes" {
		t.Fatalf("load = %+v, %v", got, err)
	}
	if ids, _ := List(cfg.Resolve(cfg.Reports.Dir)); len(ids) != 1 || ids[0] != id {
		t.Errorf("list = %q", ids)
	}

	written, err := WriteDrafts(dir, id, got, cfg, false, cet, "shipward test")
	if err != nil || len(written) != 4 {
		t.Fatalf("drafts = %q, %v", written, err)
	}
	early, _ := os.ReadFile(filepath.Join(dir, "early-warning.md"))
	for _, want := range []string{"Due Fri 6 Nov 2026 15:00 CET", "to SI-CERT", "All EU Member States",
		"Suspected to be caused by unlawful or malicious acts | yes", "CRA Article 14(4)(a))"} {
		if !strings.Contains(string(early), want) {
			t.Errorf("early warning lacks %q:\n%s", want, early)
		}
	}
	if strings.Contains(string(early), "14(2)") {
		t.Errorf("incident early warning cites the vulnerability article:\n%s", early)
	}
	final, _ := os.ReadFile(filepath.Join(dir, "final.md"))
	if !strings.Contains(string(final), "at the latest Tue 8 Dec 2026 15:00 CET") {
		t.Errorf("incident final before the notification:\n%s", final)
	}
	note, _ := os.ReadFile(filepath.Join(dir, "notification.md"))
	if !strings.Contains(string(note), "Initial assessment") || !strings.Contains(string(note), "- Took the server off line") ||
		!strings.Contains(string(note), "Example Game: A board game. Manufacturer") || strings.Contains(string(note), "..") {
		t.Errorf("notification:\n%s", note)
	}
	if info, _ := os.Stat(filepath.Join(dir, "users.md")); info.Mode().Perm() != 0o600 {
		t.Errorf("users.md mode %v; want private", info.Mode().Perm())
	}
	if again, _ := WriteDrafts(dir, id, got, cfg, false, cet, "shipward test"); len(again) != 0 {
		t.Errorf("drafts overwritten without force: %q", again)
	}
}

func TestVulnerabilityDrafts(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Product: config.Product{Name: "Example Game"}, Manufacturer: config.Manufacturer{Name: "Maker"}}
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	fix := aware.AddDate(0, 0, -30)
	c := &Case{Type: Vulnerability, Title: "Flaw", Aware: aware, FixAvailable: &fix}
	if _, err := WriteDrafts(dir, "id", c, cfg, false, cet, "shipward test"); err != nil {
		t.Fatal(err)
	}
	early, _ := os.ReadFile(filepath.Join(dir, "early-warning.md"))
	if !strings.Contains(string(early), "CRA Article 14(2)(a))") || strings.Contains(string(early), "14(4)") {
		t.Errorf("vulnerability early warning:\n%s", early)
	}
	final, _ := os.ReadFile(filepath.Join(dir, "final.md"))
	if !strings.Contains(string(final), "Due Sun 8 Nov 2026 15:00 CET") || !strings.Contains(string(final), "send the final report with the notification") {
		t.Errorf("final with an old fix:\n%s", final)
	}
}

func TestParseTime(t *testing.T) {
	if got, err := ParseTime("2026-11-06 14:00", cet); err != nil || !got.Equal(time.Date(2026, 11, 6, 14, 0, 0, 0, cet)) {
		t.Errorf("local form = %s, %v", got, err)
	}
	for _, s := range []string{"2026-11-06 14:00:00", "2026-11-06T14:00", " 2026-11-06T14:00:00 "} {
		if got, err := ParseTime(s, cet); err != nil || !got.Equal(time.Date(2026, 11, 6, 14, 0, 0, 0, cet)) {
			t.Errorf("%q = %s, %v", s, got, err)
		}
	}
	if got, err := ParseTime("2026-11-06T14:00:00Z", cet); err != nil || !got.Equal(time.Date(2026, 11, 6, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("UTC = %s, %v", got, err)
	}
	if _, err := ParseTime("yesterday", cet); err == nil {
		t.Error("accepted yesterday")
	}
}
