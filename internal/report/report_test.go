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

	// A fix before awareness: the real 14-day deadline holds while it is not before awareness; earlier than that, the
	// final report goes with the notification.
	for _, tc := range []struct {
		daysBefore int
		want       time.Time
		hint       string
	}{
		{5, aware.AddDate(0, 0, 9), ""},
		{11, aware.Add(72 * time.Hour), "together by then"},
		{12, aware.Add(48 * time.Hour), "together by then"},
		{14, aware, "together by then"},
		{15, aware.Add(72 * time.Hour), "ended before you became aware"},
		{30, aware.Add(72 * time.Hour), "ended before you became aware"},
	} {
		fix := aware.AddDate(0, 0, -tc.daysBefore)
		v.FixAvailable = &fix
		got := v.Deadlines()[2]
		if !got.Due.Equal(tc.want) || (tc.hint == "") != (got.Hint == "") || !strings.Contains(got.Hint, tc.hint) {
			t.Errorf("fix %d days before awareness: %+v, want due %s, hint %q", tc.daysBefore, got, tc.want, tc.hint)
		}
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

// TestMonthInZone: a saved case gives the same final deadline on every computer, also across a change to summer time.
func TestMonthInZone(t *testing.T) {
	budapest, err := time.LoadLocation("Europe/Budapest")
	if err != nil {
		t.Fatal(err)
	}
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	notification := "2026-03-25T10:00:00+01:00"
	for _, tc := range []struct {
		zone string
		want time.Time
	}{
		{"Europe/Budapest", time.Date(2026, 4, 25, 10, 0, 0, 0, budapest)},  // 10:00 summer time, 08:00 UTC
		{"", time.Date(2026, 4, 25, 10, 0, 0, 0, time.FixedZone("", 3600))}, // no zone: the offset of the notification
	} {
		var got []time.Time
		for _, local := range []*time.Location{budapest, time.UTC} {
			time.Local = local
			dir := t.TempDir()
			zone := ""
			if tc.zone != "" {
				zone = "zone: " + tc.zone + "\n"
			}
			os.WriteFile(filepath.Join(dir, "report.yaml"), []byte("type: incident\ntitle: x\n"+zone+
				"aware: 2026-03-23T10:00:00+01:00\nsubmitted:\n  early-warning: 2026-03-23T11:00:00+01:00\n  notification: "+notification+"\n"), 0o600)
			c, err := Load(dir, local)
			if err != nil {
				t.Fatal(err)
			}
			if err := Save(dir, c); err != nil {
				t.Fatal(err)
			}
			if c, err = Load(dir, local); err != nil {
				t.Fatal(err)
			}
			got = append(got, c.Deadlines()[2].Due)
		}
		if !got[0].Equal(tc.want) || !got[1].Equal(tc.want) {
			t.Errorf("zone %q: final due %s (Budapest computer), %s (UTC computer), want %s", tc.zone, got[0], got[1], tc.want)
		}
	}
}

func TestZone(t *testing.T) {
	dir := t.TempDir()
	// Times without an offset are read in the case's zone, not the computer's.
	os.WriteFile(filepath.Join(dir, "report.yaml"), []byte("type: vulnerability\ntitle: x\nzone: Europe/Budapest\naware: 2026-07-01 10:00\n"), 0o600)
	c, err := Load(dir, time.UTC)
	if err != nil || !c.Aware.Equal(time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("aware = %v, %v; want 10:00 summer time in Budapest", c, err)
	}
	if err := (Case{Type: Vulnerability, Title: "x", Aware: time.Now(), Zone: "Mars/Olympus"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), `zone "Mars/Olympus"`) {
		t.Errorf("bad zone: %v", err)
	}
	budapest, _ := time.LoadLocation("Europe/Budapest")
	if z := pickZone([]string{"", "Local", "/etc/localtime", "Mars/Olympus", "Europe/Budapest"}, budapest); z != "Europe/Budapest" {
		t.Errorf("pickZone = %q", z)
	}
	if z := pickZone([]string{"Europe/Budapest"}, time.FixedZone("", -5*3600)); z != "" {
		t.Errorf("pickZone with another offset = %q, want empty", z)
	}
}

func TestIntermediateSkippedAndNext(t *testing.T) {
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	c := Case{Type: Incident, Title: "x", Aware: aware}
	if _, ok := c.Deadline(Intermediate); ok {
		t.Error("intermediate without a CSIRT request")
	}
	// The users' notice is not part of the report order: Next skips it, Closed needs it.
	c.Submitted = map[string]time.Time{EarlyWarning: aware, Notification: aware.Add(time.Hour), Final: aware.Add(2 * time.Hour)}
	if _, open := c.Next(); open || c.Closed() {
		t.Errorf("all reports sent: next open %v, closed %v", open, c.Closed())
	}
	c.Submitted[Users] = aware
	if !c.Closed() {
		t.Error("not closed with every stage sent")
	}

	due := aware.Add(10 * 24 * time.Hour)
	c = Case{Type: Incident, Title: "x", Aware: aware, IntermediateDue: &due,
		Submitted: map[string]time.Time{EarlyWarning: aware, Notification: aware.Add(time.Hour)}}
	if next, _ := c.Next(); next.Stage != Intermediate || !next.Due.Equal(due) {
		t.Errorf("next = %+v, want the intermediate report", next)
	}
	if d, _ := c.Deadline(EarlyWarning); !d.UndueDelay {
		t.Error("early warning lacks without undue delay")
	}
	if d, _ := c.Deadline(Final); d.UndueDelay {
		t.Error("final report has without undue delay")
	}

	c.Skipped = map[string]string{Notification: "already provided in the early warning"}
	if err := c.Validate(); err != nil {
		t.Errorf("skipped notification: %v", err)
	}
	// A skip recorded late does not move the final report: the month counts from the early warning.
	inc := Case{Type: Incident, Title: "x", Aware: time.Date(2026, 11, 1, 10, 0, 0, 0, cet),
		Submitted: map[string]time.Time{EarlyWarning: time.Date(2026, 11, 1, 12, 0, 0, 0, cet), Notification: time.Date(2026, 11, 11, 9, 0, 0, 0, cet)},
		Skipped:   map[string]string{Notification: "already provided in the early warning"}}
	if d, _ := inc.Deadline(Final); !d.Due.Equal(time.Date(2026, 12, 1, 12, 0, 0, 0, cet)) || d.Hint == "" {
		t.Errorf("final after a skipped notification = %+v, want 1 Dec 12:00 (a month after the early warning)", d)
	}
	dir := t.TempDir()
	cfg := &config.Config{Product: config.Product{Name: "P"}, Manufacturer: config.Manufacturer{Name: "M"}}
	if _, err := WriteDrafts(dir, "id", &inc, cfg, false, cet, "shipward test"); err != nil {
		t.Fatal(err)
	}
	if final, _ := os.ReadFile(filepath.Join(dir, "final.md")); !strings.Contains(string(final), "At the latest Tue 1 Dec 2026 12:00 CET") ||
		!strings.Contains(string(final), "Note: the notification was skipped, so the month counts from the early warning.") {
		t.Errorf("final draft after a skipped notification:\n%s", final)
	}
	delete(inc.Skipped, Notification)
	if d, _ := inc.Deadline(Final); !d.Due.Equal(time.Date(2026, 12, 11, 9, 0, 0, 0, cet)) || d.Hint != "" {
		t.Errorf("final after a sent notification = %+v", d)
	}
	if d, _ := c.Deadline(Notification); d.Skipped == "" || d.Done.IsZero() {
		t.Errorf("skipped notification = %+v", d)
	}
	err := Case{Type: Vulnerability, Title: "x", Aware: aware, Submitted: map[string]time.Time{EarlyWarning: aware, Intermediate: aware},
		Skipped: map[string]string{EarlyWarning: "x", Final: " "}}.Validate()
	for _, want := range []string{"early-warning cannot be skipped", "final needs a reason", "final is not in submitted", "no CSIRT request"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
	}
}

func TestIntermediateDraft(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Product: config.Product{Name: "Example Game"}, Manufacturer: config.Manufacturer{Name: "Maker"}}
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	c := &Case{Type: Incident, Title: "Hit", Aware: aware}
	written, err := WriteDrafts(dir, "id", c, cfg, false, cet, "shipward test")
	if err != nil || len(written) != 4 {
		t.Fatalf("drafts = %q, %v", written, err)
	}
	due := aware.AddDate(0, 0, 10)
	c.IntermediateDue = &due
	written, err = WriteDrafts(dir, "id", c, cfg, false, cet, "shipward test")
	if err != nil || len(written) != 1 || filepath.Base(written[0]) != "intermediate.md" {
		t.Fatalf("drafts after the request = %q, %v", written, err)
	}
	body, _ := os.ReadFile(written[0])
	if !strings.Contains(string(body), "at the latest Sun 15 Nov 2026 15:00 CET") || !strings.Contains(string(body), "14(6)") {
		t.Errorf("intermediate:\n%s", body)
	}
	users, _ := os.ReadFile(filepath.Join(dir, "users.md"))
	for _, want := range []string{"in parallel with the reports", "not how the flaw works", "Annex I Part II(4)", "machine-readable"} {
		if !strings.Contains(string(users), want) {
			t.Errorf("users notice lacks %q:\n%s", want, users)
		}
	}
	note, _ := os.ReadFile(filepath.Join(dir, "notification.md"))
	if !strings.Contains(string(note), `--skipped "already provided in the early warning"`) ||
		!strings.Contains(string(note), "The final report is then due one month after the early warning.") {
		t.Errorf("notification:\n%s", note)
	}
}

func TestIgnoreCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cra", "reports")
	wrote, err := IgnoreCases(dir)
	if err != nil || !wrote {
		t.Fatalf("IgnoreCases = %v, %v", wrote, err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if !strings.HasSuffix(string(body), "\n*\n") {
		t.Errorf(".gitignore:\n%s", body)
	}
	// A file the person changed (or deleted on purpose and wrote again) is kept.
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("# keep\n"), 0o644)
	if wrote, err := IgnoreCases(dir); err != nil || wrote {
		t.Errorf("second IgnoreCases = %v, %v", wrote, err)
	}
	if got := withoutUser("https://user:ghp_secret@github.com/o/r.git"); got != "https://github.com/o/r.git" {
		t.Errorf("withoutUser = %q", got)
	}
	if got := withoutUser("git@github.com:o/r.git"); got != "git@github.com:o/r.git" {
		t.Errorf("withoutUser scp = %q", got)
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
	for _, want := range []string{"Send it without undue delay, at the latest Fri 6 Nov 2026 15:00 CET", "to SI-CERT", "All EU Member States",
		"### i31. Suspected of unlawful or malicious acts (max. 255 characters)\n\nyes", "CRA Article 14(4)(a))",
		"### i37. Became aware (UTC)\n\n2026-11-05 14:00 UTC (Thu 5 Nov 2026 15:00 CET)", "CRA SRP Glossary, version 1.6"} {
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
	if !strings.Contains(string(note), "### i39. Initial assessment (required, max. 4000 characters)") ||
		!strings.Contains(string(note), "- Took the server off line") || !strings.Contains(string(note), "The product: A board game.") ||
		strings.Contains(string(note), "..") || strings.Contains(string(note), "v21.") || strings.Contains(string(note), "v28") {
		t.Errorf("notification:\n%s", note)
	}
	if info, _ := os.Stat(filepath.Join(dir, "users.md")); info.Mode().Perm() != 0o600 {
		t.Errorf("users.md mode %v; want private", info.Mode().Perm())
	}
	if again, _ := WriteDrafts(dir, id, got, cfg, false, cet, "shipward test"); len(again) != 0 {
		t.Errorf("drafts overwritten without force: %q", again)
	}
}

// TestDraftsFollowTheForm: the drafts carry ENISA's field numbers in order, the limits, the awareness time in UTC
// and the new fields of report.yaml.
func TestDraftsFollowTheForm(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Product: config.Product{Name: "Example Game", SupportUntil: "2031-12"}, Manufacturer: config.Manufacturer{Name: "Maker"}}
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	occurred := aware.Add(-48 * time.Hour)
	c := &Case{Type: Vulnerability, Title: strings.Repeat("x", 256), Aware: aware, Occurred: &occurred,
		Summary: "An exploited flaw in the login.", Advisories: []string{"GHSA-aaaa", "CVE-2026-1234", "EUVD-2026-5"},
		Versions: []string{"1.3.0", "1.3.1"}, ProductType: "default", MitigationExpected: "yes", AttackVector: "Network, no login.",
		Severity: "High.", Impact: "Account takeover."}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteDrafts(dir, "id", c, cfg, false, cet, "shipward test"); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return string(b)
	}
	inOrder := func(name, body string, parts ...string) {
		at := 0
		for _, p := range parts {
			i := strings.Index(body[at:], p)
			if i < 0 {
				t.Errorf("%s lacks %q after position %d:\n%s", name, p, at, body)
				return
			}
			at += i + len(p)
		}
	}
	early := read("early-warning.md")
	inOrder("early warning", early, "### 1. Notification type", "Actively exploited vulnerability", "### 2. Title (max. 255 characters)",
		"**Too long for the form: 256 characters, the field takes 255.**", "### 3. Summary", "An exploited flaw in the login.",
		"### 5. Member States", "### 6. Product name", "### 7. Product version", "1.3.0, 1.3.1",
		"### v26. Became aware (UTC)", "2026-11-05 14:00 UTC", "**8. Product type**: default",
		"**11. End of the support period reached**: No (support until the end of December 2031)",
		"**13. Mitigating measure expected shortly**: yes", "**v19. CVE ID**: CVE-2026-1234", "**v20. EUVD ID**: EUVD-2026-5",
		"**v26a. Occurred (UTC)**: 2026-11-03 14:00 UTC")
	note := read("notification.md")
	inOrder("notification", note, "Became aware: 2026-11-05 14:00 UTC", "### v21. General information (required", "Advisories: GHSA-aaaa",
		"### 15. Sensitivity", "### 16.", "### 17.", "### 18. Attack vector", "Network, no login.", "### v24. Severity", "High.",
		"### v25. Impact", "Account takeover.", "### v28-v30. Particularly exceptional circumstances")
	final := read("final.md")
	inOrder("final", final, "All are required here", "### 16.", "### 17.", "### v22.", "### v23.", "### v24.", "High.", "### v25.",
		"Account takeover.", "### v27. Malicious actor (max. 100 characters")

	if endOfSupport("2025-06", aware) != "Yes (support ended at the end of June 2025)" || endOfSupport("", aware) != "" ||
		endOfSupport("2026-11", aware) != "No (support until the end of November 2026)" {
		t.Errorf("endOfSupport = %q, %q", endOfSupport("2025-06", aware), endOfSupport("2026-11", aware))
	}
	err := Case{Type: Incident, Title: "x", Aware: aware, ProductType: "important-1", ProductClass: "1", MitigationExpected: "soon"}.Validate()
	if err := (Case{Type: Incident, Title: "x", Aware: aware, ProductType: "default", ProductClass: "class-ii"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "only for product_type important") {
		t.Errorf("class on a default product: %v", err)
	}
	if err := (Case{Type: Incident, Title: "x", Aware: aware, ProductType: "important", ProductClass: "class-ii"}).Validate(); err != nil {
		t.Errorf("important class II: %v", err)
	}
	for _, want := range []string{`product_type "important-1"`, `product_class "1"`, `mitigation_expected "soon"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
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
	if !strings.Contains(string(final), "At the latest Sun 8 Nov 2026 15:00 CET") || !strings.Contains(string(final), "Note: the 14 days after the fix ended before you became aware: send the final report with the notification.") {
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
