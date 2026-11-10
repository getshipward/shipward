package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportFlow(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "shipward.yaml")
	os.WriteFile(cfg, []byte("product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n"), 0o644)
	now := time.Now()
	aware := now.Add(-30 * time.Hour).Format(time.RFC3339)

	var out, errOut bytes.Buffer
	if code := reportNew([]string{"vulnerability", "--config", cfg, "--title", "Test flaw", "--aware", aware}, &out, &errOut, now); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "early-warning  OVERDUE") {
		t.Errorf("new output:\n%s", out.String())
	}
	id := strings.Fields(out.String())[1]

	out.Reset()
	if code := reportList([]string{"--config", cfg, "--fail-on", "overdue"}, &out, &errOut, now); code != exitFindings {
		t.Errorf("list with an overdue report: exit %d", code)
	}
	for _, stage := range []string{"early-warning", "notification"} {
		if code := reportMark("done", []string{id, stage, "--config", cfg}, &out, &errOut, now); code != 0 {
			t.Fatalf("done %s: %d %s", stage, code, errOut.String())
		}
	}
	out.Reset()
	if code := reportList([]string{"--config", cfg, "--fail-on", "overdue"}, &out, &errOut, now); code != 0 {
		t.Errorf("list after sending: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "at the latest 14 days after a fix is available") {
		t.Errorf("list:\n%s", out.String())
	}
	if code := reportMark("done", []string{id, "later", "--config", cfg}, &out, &errOut, now); code != 2 {
		t.Errorf("unknown stage: exit %d", code)
	}
}

func TestReportRefusesImpossibleInput(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "shipward.yaml")
	os.WriteFile(cfg, []byte("product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n"), 0o644)
	now := time.Now()
	awareAt := now.Add(-30 * time.Hour).Truncate(time.Second)
	aware := awareAt.Format(time.RFC3339)
	var out, errOut bytes.Buffer
	open := func(kind, title string) string {
		out.Reset()
		if code := reportNew([]string{kind, "--config", cfg, "--title", title, "--aware", aware}, &out, &errOut, now); code != 0 {
			t.Fatalf("new: %d %s", code, errOut.String())
		}
		return strings.Fields(out.String())[1]
	}
	vuln, inc := open("vulnerability", "Flaw"), open("incident", "Server hit")

	if code := reportList([]string{"--config", cfg, "--fail-on", "overdeu"}, &out, &errOut, now); code != 2 {
		t.Errorf("--fail-on typo: exit %d", code)
	}
	future := now.Add(time.Hour).Format(time.RFC3339)
	before := awareAt.Add(-time.Hour).Format(time.RFC3339)
	for _, tc := range []struct {
		name, kind string
		args       []string
		want       string
	}{
		{"done in the future", "done", []string{vuln, "early-warning", "--at", future}, "in the future"},
		{"fixed in the future", "fixed", []string{vuln, "--at", future}, "in the future"},
		{"done before aware", "done", []string{vuln, "early-warning", "--at", before}, "before you became aware"},
		{"notification before the early warning", "done", []string{vuln, "notification"}, "record the early-warning first"},
		{"final before the notification", "done", []string{vuln, "final"}, "record the notification first"},
		{"fixed on an incident", "fixed", []string{inc}, "is an incident"},
	} {
		errOut.Reset()
		if code := reportMark(tc.kind, append(tc.args, "--config", cfg), &out, &errOut, now); code != 2 || !strings.Contains(errOut.String(), tc.want) {
			t.Errorf("%s: exit %d, %q", tc.name, code, errOut.String())
		}
	}

	// The notification may not be earlier than the early warning.
	if code := reportMark("done", []string{vuln, "early-warning", "--config", cfg}, &out, &errOut, now); code != 0 {
		t.Fatalf("done early-warning: %d %s", code, errOut.String())
	}
	errOut.Reset()
	if code := reportMark("done", []string{vuln, "notification", "--at", awareAt.Format(time.RFC3339), "--config", cfg}, &out, &errOut, now); code != 2 ||
		!strings.Contains(errOut.String(), "before the early-warning was sent") {
		t.Errorf("notification before the early warning: exit %d, %q", code, errOut.String())
	}

	// A fix long before awareness: the final report goes with the notification, it is not overdue at once.
	out.Reset()
	if code := reportMark("fixed", []string{vuln, "--at", awareAt.AddDate(0, 0, -30).Format(time.RFC3339), "--config", cfg}, &out, &errOut, now); code != 0 {
		t.Fatalf("fixed before aware: %d %s", code, errOut.String())
	}
	out.Reset()
	if code := reportList([]string{"--config", cfg}, &out, &errOut, now); code != 0 {
		t.Errorf("list: exit %d\n%s", code, out.String())
	}
	for _, want := range []string{"send the final report with the notification", "final          at the latest"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "final          OVERDUE") {
		t.Errorf("final shown overdue:\n%s", out.String())
	}
}

func TestReportNewRecordsZone(t *testing.T) {
	budapest, err := time.LoadLocation("Europe/Budapest")
	if err != nil {
		t.Fatal(err)
	}
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = budapest
	t.Setenv("TZ", "Europe/Budapest")

	dir := t.TempDir()
	cfg := filepath.Join(dir, "shipward.yaml")
	os.WriteFile(cfg, []byte("product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n"), 0o644)
	var out, errOut bytes.Buffer
	if code := reportNew([]string{"incident", "--config", cfg, "--title", "Zoned"}, &out, &errOut, time.Now()); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	id := strings.Fields(out.String())[1]
	body, _ := os.ReadFile(filepath.Join(dir, "cra", "reports", id, "report.yaml"))
	if !strings.Contains(string(body), "\nzone: Europe/Budapest\n") {
		t.Errorf("report.yaml lacks the zone:\n%s", body)
	}
}

func TestReportWorkflow(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "shipward.yaml")
	os.WriteFile(cfg, []byte("product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n"), 0o644)
	now := time.Now()
	aware := now.Add(-2 * time.Hour).Truncate(time.Second)
	var out, errOut bytes.Buffer
	if code := reportNew([]string{"incident", "--config", cfg, "--title", "Hit", "--aware", aware.Format(time.RFC3339)}, &out, &errOut, now); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	id := strings.Fields(out.String())[1]
	// The users' notice is shown first, in parallel; the 24- and 72-hour reports say "without undue delay".
	lines := out.String()
	if u, e := strings.Index(lines, "    users"), strings.Index(lines, "    early-warning"); u < 0 || e < 0 || u > e {
		t.Errorf("users is not listed first:\n%s", lines)
	}
	if !strings.Contains(lines, "early-warning  without undue delay, at the latest") || !strings.Contains(lines, "git ignores the cases") {
		t.Errorf("new output:\n%s", lines)
	}
	if body, err := os.ReadFile(filepath.Join(dir, "cra", "reports", ".gitignore")); err != nil || !strings.Contains(string(body), "\n*\n") {
		t.Errorf(".gitignore: %q %v", body, err)
	}

	mark := func(kind string, args ...string) int {
		out.Reset()
		errOut.Reset()
		return reportMark(kind, append(args, "--config", cfg), &out, &errOut, now)
	}
	if code := mark("done", id, "early-warning", "--skipped", "x"); code != 2 || !strings.Contains(errOut.String(), "only for notification and final") {
		t.Errorf("skip early warning: %d %s", code, errOut.String())
	}
	if code := mark("done", id, "early-warning"); code != 0 || !strings.Contains(out.String(), "Also open, in parallel: users") {
		t.Errorf("done early-warning: %d %s%s", code, out.String(), errOut.String())
	}
	if code := mark("done", id, "notification", "--skipped", "already provided in the early warning"); code != 0 {
		t.Fatalf("skip notification: %d %s", code, errOut.String())
	}
	if code := mark("done", id, "intermediate"); code != 2 || !strings.Contains(errOut.String(), "no intermediate report was asked for") {
		t.Errorf("intermediate without a request: %d %s", code, errOut.String())
	}
	if code := mark("intermediate", id); code != 2 {
		t.Errorf("intermediate without --due: %d", code)
	}
	due := now.Add(48 * time.Hour).Format(time.RFC3339)
	if code := mark("intermediate", id, "--due", due); code != 0 || !strings.Contains(out.String(), "intermediate.md") ||
		!strings.Contains(out.String(), "Next: intermediate") {
		t.Errorf("intermediate: %d %s%s", code, out.String(), errOut.String())
	}
	if code := mark("done", id, "intermediate"); code != 0 {
		t.Fatalf("done intermediate: %d %s", code, errOut.String())
	}
	out.Reset()
	reportList([]string{"--config", cfg}, &out, &errOut, now)
	for _, want := range []string{"notification   not sent (already provided in the early warning), recorded", "intermediate   sent", "final          at the latest", "the month counts from the early warning"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, out.String())
		}
	}
	// All reports sent, users still open: the case stays listed.
	mark("done", id, "final")
	out.Reset()
	reportList([]string{"--config", cfg}, &out, &errOut, now)
	if !strings.Contains(out.String(), id) {
		t.Errorf("case with an open users' notice is hidden:\n%s", out.String())
	}
	mark("done", id, "users")
	out.Reset()
	reportList([]string{"--config", cfg}, &out, &errOut, now)
	if !strings.Contains(out.String(), "No open cases") {
		t.Errorf("closed case still listed:\n%s", out.String())
	}
}

func TestReportNewWarnsWhenTracked(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "https://user:secret@example.com/o/r.git"}} {
		if out, err := exec.Command(git, append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	cfg := filepath.Join(dir, "shipward.yaml")
	os.WriteFile(cfg, []byte("product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n"), 0o644)
	// The person removed the ignore file on purpose: warn, and keep the token out of the message.
	os.MkdirAll(filepath.Join(dir, "cra", "reports"), 0o700)
	os.WriteFile(filepath.Join(dir, "cra", "reports", ".gitignore"), []byte("# kept in this private repository\n"), 0o644)
	var out, errOut bytes.Buffer
	if code := reportNew([]string{"vulnerability", "--config", cfg, "--title", "Flaw"}, &out, &errOut, time.Now()); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "git does not ignore") || !strings.Contains(errOut.String(), "origin: https://example.com/o/r.git") ||
		strings.Contains(errOut.String(), "secret") {
		t.Errorf("warning:\n%s", errOut.String())
	}

	// The folder exists: no .gitignore is written behind the person's back.
	os.Remove(filepath.Join(dir, "cra", "reports", ".gitignore"))
	errOut.Reset()
	out.Reset()
	if code := reportNew([]string{"vulnerability", "--config", cfg, "--title", "Other"}, &out, &errOut, time.Now()); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "cra", "reports", ".gitignore")); err == nil || strings.Contains(out.String(), "git ignores") {
		t.Errorf("wrote .gitignore into an existing folder:\n%s", out.String())
	}

	// A new folder gets the ignore file, and then no warning.
	os.RemoveAll(filepath.Join(dir, "cra"))
	errOut.Reset()
	if code := reportNew([]string{"vulnerability", "--config", cfg, "--title", "Third"}, &out, &errOut, time.Now()); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "warning") {
		t.Errorf("warning with the ignore file:\n%s", errOut.String())
	}
}
