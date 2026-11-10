package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getshipward/shipward/internal/config"
)

func TestNotice(t *testing.T) {
	cfg := &config.Config{Product: config.Product{Name: "Example Game"},
		Manufacturer: config.Manufacturer{Name: "Maker", URL: "https://example.com"}}
	aware := time.Date(2026, 11, 5, 15, 0, 0, 0, cet)
	c := &Case{Type: Vulnerability, Title: "Login flaw", Aware: aware, Versions: []string{"1.3.0"},
		Advisories: []string{"GHSA-aaaa", "CVE-2026-1234"}, Summary: "Attackers take over accounts.",
		UserMeasures: []string{"Turn off online play.", "Update when 1.3.2 is out."}}
	dir := t.TempDir()
	wrote, err := WriteNotice(dir, "2026-11-05-login-flaw", c, cfg, aware, "shipward test", false)
	if err != nil || !wrote {
		t.Fatalf("WriteNotice = %v, %v", wrote, err)
	}
	path := filepath.Join(dir, NoticeFile)
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v; want private", info.Mode().Perm())
	}
	body, _ := os.ReadFile(path)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"category": "csaf_security_advisory"`, `"title": "Security notice: Login flaw"`,
		`"id": "GHSA-aaaa"`, `"cve": "CVE-2026-1234"`, `"category": "mitigation"`, "Turn off online play.\nUpdate when",
		"Attackers take over accounts.", `"status": "draft"`} {
		if !strings.Contains(string(body), strings.ReplaceAll(want, "\n", `\n`)) {
			t.Errorf("notice lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(string(body), `"fixed"`) {
		t.Errorf("notice before a fix names a fixed product:\n%s", body)
	}
	if wrote, err := WriteNotice(dir, "x", c, cfg, aware, "shipward test", false); err != nil || wrote {
		t.Errorf("overwrote without force: %v, %v", wrote, err)
	}

	if _, err := Notice("x", &Case{Type: Incident, Title: "y", Aware: aware}, cfg, aware, "t"); err == nil ||
		!strings.Contains(err.Error(), "versions in report.yaml") {
		t.Errorf("notice without versions: %v", err)
	}
	c.UserMeasures, cfg.Manufacturer.URL = nil, ""
	if _, err := Notice("x", c, cfg, aware, "t"); err == nil || !strings.Contains(err.Error(), "user_measures") ||
		!strings.Contains(err.Error(), "manufacturer.url") {
		t.Errorf("incomplete notice: %v", err)
	}
}
