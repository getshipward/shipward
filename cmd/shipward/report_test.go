package main

import (
	"bytes"
	"os"
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
	if !strings.Contains(out.String(), "due 14 days after a fix is available") {
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
	for _, want := range []string{"send the final report with the notification", "final          due at the latest"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "final          OVERDUE") {
		t.Errorf("final shown overdue:\n%s", out.String())
	}
}
