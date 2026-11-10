package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getshipward/shipward/internal/config"
)

func TestAdvisoryNew(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"shipward.yaml": "product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n  url: https://example.com\n  email: sec@example.com\n",
		"vex.yaml": "- id: GHSA-aaaa\n  component: pkg:nuget/Lib@1.0.0\n  status: fixed\n  fixed_in: 1.4.0\n  date: \"2026-11-01\"\n" +
			"- id: GHSA-bbbb\n  component: pkg:nuget/Other@2.0.0\n  status: affected\n  action: Update to 1.4.1.\n  date: \"2026-11-01\"\n",
	})
	cfg := filepath.Join(dir, "shipward.yaml")
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	var out, errOut bytes.Buffer
	if code := advisoryNew(context.Background(), []string{"GHSA-aaaa", "--config", cfg, "--affected", "1.3.0", "--csaf"}, &out, &errOut, now); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	md, _ := os.ReadFile(filepath.Join(dir, "cra", "advisories", "GHSA-aaaa.md"))
	for _, want := range []string{"| Fixed in | 1.4.0 |", "`pkg:nuget/Lib@1.0.0`", "| Affected versions | 1.3.0 |", "Questions: sec@example.com."} {
		if !strings.Contains(string(md), want) {
			t.Errorf("advisory lacks %q:\n%s", want, md)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "cra", "advisories", "GHSA-aaaa.csaf.json")); err != nil {
		t.Error(err)
	}
	if !strings.Contains(out.String(), "shipward triage set GHSA-aaaa pkg:nuget/Lib@1.0.0 --status fixed --fixed-in 1.4.0 --advisory URL") {
		t.Errorf("output:\n%s", out.String())
	}

	// No overwrite without --force.
	errOut.Reset()
	if code := advisoryNew(context.Background(), []string{"GHSA-aaaa", "--config", cfg}, &out, &errOut, now); code != 1 || !strings.Contains(errOut.String(), "--force") {
		t.Errorf("overwrite: exit %d %s", code, errOut.String())
	}
	// The decision's action is the remediation.
	if code := advisoryNew(context.Background(), []string{"GHSA-bbbb", "--config", cfg}, &out, &errOut, now); code != 0 {
		t.Fatalf("new: %d %s", code, errOut.String())
	}
	md, _ = os.ReadFile(filepath.Join(dir, "cra", "advisories", "GHSA-bbbb.md"))
	if !strings.Contains(string(md), "Update to 1.4.1.") {
		t.Errorf("remediation from vex.yaml:\n%s", md)
	}
	// CSAF without what it needs: nothing is written.
	errOut.Reset()
	if code := advisoryNew(context.Background(), []string{"OWN-2026-1", "--config", cfg, "--csaf"}, &out, &errOut, now); code != 2 || !strings.Contains(errOut.String(), "--affected") {
		t.Errorf("csaf without versions: exit %d %s", code, errOut.String())
	}
	if code := runAdvisory(context.Background(), []string{"publish"}, &out, &errOut); code != 2 {
		t.Errorf("unknown subcommand: exit %d", code)
	}
}

func TestTriageFixedNeedsAdvisory(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"shipward.yaml": "product:\n  name: Example Game\nmanufacturer:\n  name: Maker\n"})
	cfgPath := filepath.Join(dir, "shipward.yaml")
	var out, errOut bytes.Buffer
	if code := triageSet([]string{"GHSA-aaaa", "pkg:npm/a@1.0.0", "--status", "fixed", "--config", cfgPath}, &out, &errOut); code != 0 {
		t.Fatalf("set: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "shipward advisory new GHSA-aaaa") {
		t.Errorf("set fixed gives no hint:\n%s", out.String())
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	printNeedsAdvisory(&out, cfg)
	if !strings.Contains(out.String(), "not recorded yet") || !strings.Contains(out.String(), "--fixed-in VERSION --advisory URL") {
		t.Errorf("list:\n%s", out.String())
	}

	out.Reset()
	if code := triageSet([]string{"GHSA-aaaa", "pkg:npm/a@1.0.0", "--status", "fixed", "--fixed-in", "1.1.0",
		"--advisory", "https://example.com/a", "--config", cfgPath}, &out, &errOut); code != 0 {
		t.Fatalf("set: %d %s", code, errOut.String())
	}
	if strings.Contains(out.String(), "advisory new") {
		t.Errorf("hint after recording:\n%s", out.String())
	}
	out.Reset()
	printNeedsAdvisory(&out, cfg)
	if out.Len() != 0 {
		t.Errorf("still listed:\n%s", out.String())
	}
	body, _ := os.ReadFile(filepath.Join(dir, "vex.yaml"))
	if !strings.Contains(string(body), "fixed_in: 1.1.0") || !strings.Contains(string(body), "advisory: https://example.com/a") {
		t.Errorf("vex.yaml:\n%s", body)
	}
}
