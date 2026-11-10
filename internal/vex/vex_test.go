package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Statement{ID: "GHSA-1", Component: "pkg:npm/a@1.0.0", Status: NotAffected, Justification: "component_not_present", Date: "2026-11-06"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		s    Statement
		want string
	}{
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: NotAffected, Date: "2026-11-06"}, "needs a justification or an impact"},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Affected, Date: "2026-11-06"}, "needs an action"},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: "maybe", Date: "2026-11-06"}, `status "maybe"`},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Justification: "component_not_present", Date: "2026-11-06"}, "only for not_affected"},
		{Statement{ID: "GHSA-1", Component: "left-pad", Status: Fixed, Date: "2026-11-06"}, "not a purl"},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Date: "6.11.2026"}, "YYYY-MM-DD"},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Affected, Action: "update", FixedIn: "1.2", Date: "2026-11-06"}, "only for fixed"},
	}
	for _, b := range bad {
		if err := b.s.Validate(); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("Validate(%+v) = %v, want %q", b.s, err, b.want)
		}
	}
}

func TestSetKeepsCommentsAndReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vex.yaml")
	first := Statement{ID: "GHSA-1", Component: "pkg:nuget/Lib@1.0.0", Status: UnderInvestigation, Date: "2026-11-01"}
	if err := Set(path, first); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	data = []byte(strings.Replace(string(data), "- id: GHSA-1", "# checked with the team\n- id: GHSA-1", 1))
	os.WriteFile(path, data, 0o644)

	second := Statement{ID: "GHSA-2", Component: "pkg:nuget/Other", Status: Fixed, Date: "2026-11-02"}
	if err := Set(path, second); err != nil {
		t.Fatal(err)
	}
	first.Status, first.Impact, first.Date = NotAffected, "Never called.", "2026-11-06"
	if err := Set(path, first); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	for _, want := range []string{"# Decisions about advisories", "# checked with the team", "impact: Never called."} {
		if !strings.Contains(string(data), want) {
			t.Errorf("vex.yaml lost %q:\n%s", want, data)
		}
	}
	list, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Status != NotAffected || list[1].ID != "GHSA-2" {
		t.Errorf("list = %+v", list)
	}
}

func TestFind(t *testing.T) {
	list := []Statement{
		{ID: "CVE-1", Component: "pkg:nuget/Lib", Status: UnderInvestigation},
		{ID: "CVE-1", Component: "pkg:nuget/Lib@1.0.0", Status: NotAffected},
	}
	if s := Find(list, []string{"GHSA-1", "CVE-1"}, "pkg:nuget/lib@1.0.0?package-id=x"); s == nil || s.Status != NotAffected {
		t.Errorf("exact version: %+v", s)
	}
	if s := Find(list, []string{"CVE-1"}, "pkg:nuget/Lib@2.0.0"); s == nil || s.Status != UnderInvestigation {
		t.Errorf("every version: %+v", s)
	}
	if s := Find(list, []string{"CVE-2"}, "pkg:nuget/Lib@1.0.0"); s != nil {
		t.Errorf("other advisory: %+v", s)
	}
}

func TestExport(t *testing.T) {
	list := []Statement{
		{ID: "GHSA-1", Component: "pkg:npm/a", Status: NotAffected, Justification: "component_not_present", Date: "2026-11-05"},
		{ID: "GHSA-2", Component: "pkg:npm/b@1.0.0", Status: Fixed, Date: "2026-11-06"},
		{ID: "GHSA-3", Component: "pkg:npm/gone@1.0.0", Status: Fixed, Date: "2026-11-01"},
	}
	targets := []string{"pkg:npm/a@1.0.0", "pkg:npm/a@2.0.0", "pkg:npm/b@1.0.0"}
	doc, err := Export("Maker", "shipward test", "urn:cdx:x/1#product", list, targets, map[string][]string{"GHSA-1": {"CVE-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 2 || doc.Timestamp != "2026-11-06T00:00:00Z" {
		t.Fatalf("doc = %+v; want 2 statements (the component no longer shipped is left out)", doc)
	}
	s := doc.Statements[0]
	if s.Vulnerability.Name != "GHSA-1" || s.Vulnerability.Aliases[0] != "CVE-1" || len(s.Products[0].Subcomponents) != 2 {
		t.Errorf("statement = %+v; want both shipped versions of a", s)
	}
	again, _ := Export("Maker", "shipward test", "urn:cdx:x/1#product", list, targets, map[string][]string{"GHSA-1": {"CVE-1"}})
	if again.ID != doc.ID {
		t.Error("the same input gave another @id")
	}
}

func TestNeedsAdvisory(t *testing.T) {
	s := Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Date: "2026-11-06"}
	if !s.NeedsAdvisory() {
		t.Error("bare fixed needs no advisory")
	}
	s.FixedIn = "1.4.0"
	if !s.NeedsAdvisory() {
		t.Error("fixed without an advisory needs none")
	}
	s.Advisory = "https://example.com/advisories/GHSA-1"
	if s.NeedsAdvisory() || s.Validate() != nil {
		t.Errorf("recorded fixed: needs %v, %v", s.NeedsAdvisory(), s.Validate())
	}
	if (Statement{Status: NotAffected}).NeedsAdvisory() {
		t.Error("not_affected needs an advisory")
	}
}
