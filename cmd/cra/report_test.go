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
	cfg := filepath.Join(dir, "cra.yaml")
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
