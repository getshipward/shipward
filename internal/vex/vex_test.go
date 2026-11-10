package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	ok := Statement{ID: "GHSA-1", Component: "pkg:npm/a@1.0.0", Status: NotAffected, Justification: "component_not_present", Date: "2026-11-06"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	full := Statement{ID: "GHSA-1", Component: "pkg:npm/a@1.0.0", Status: Affected, Action: "Update.", Date: "2026-11-06T14:30:00+01:00",
		Upstream: &Upstream{Reported: "2026-11-07", Link: "https://github.com/a/a/issues/4", FixShared: true}}
	if err := full.Validate(); err != nil {
		t.Errorf("RFC 3339 date and upstream: %v", err)
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
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Advisory: "cra/advisories/GHSA-1.md", Date: "2026-11-06"}, "is not a URL"},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Date: "2026-11-06T14:00:00"}, "RFC 3339"}, // no offset
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Date: "2026-11-06", Upstream: &Upstream{Reported: "soon"}}, "upstream.reported"},
		{Statement{ID: "GHSA-1", Component: "pkg:npm/a", Status: Fixed, Date: "2026-11-06", Upstream: &Upstream{Link: "issue 4"}}, "upstream.link"},
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
		{ID: "GHSA-2", Component: "pkg:npm/b@1.0.0", Status: Fixed, Date: "2026-11-06T14:30:00+01:00"},
		{ID: "GHSA-3", Component: "pkg:npm/gone@1.0.0", Status: Fixed, Date: "2026-11-01"},
	}
	targets := []string{"pkg:npm/a@1.0.0", "pkg:npm/a@2.0.0", "pkg:npm/b@1.0.0"}
	aliases := map[string][]string{"GHSA-1": {"CVE-1"}}
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	product := "pkg:generic/App@1.4.0"
	doc, err := Export("Maker", "shipward test", product, list, targets, aliases, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 2 || doc.Timestamp != "2026-11-06T13:30:00Z" || doc.Version != 1 || doc.LastUpdated != "" {
		t.Fatalf("doc = %+v; want 2 statements (the component no longer shipped is left out), the newest time, version 1", doc)
	}
	s := doc.Statements[0]
	if s.Vulnerability.Name != "GHSA-1" || s.Vulnerability.Aliases[0] != "CVE-1" || len(s.Products[0].Subcomponents) != 2 ||
		s.Timestamp != "2026-11-05T00:00:00Z" || s.Products[0].ID != product || s.Products[0].Identifiers["purl"] != product {
		t.Errorf("statement = %+v; want both shipped versions of a, the date as midnight UTC, the product purl", s)
	}
	if doc.Statements[1].Timestamp != "2026-11-06T13:30:00Z" {
		t.Errorf("full time = %s; want it in UTC", doc.Statements[1].Timestamp)
	}

	// The same input, a later run: the same document, version and times.
	again, _ := Export("Maker", "shipward test", product, list, targets, aliases, &doc, now.Add(time.Hour))
	if again.ID != doc.ID || again.Version != 1 || again.Timestamp != doc.Timestamp || again.LastUpdated != "" {
		t.Errorf("unchanged input: %+v", again)
	}

	// A changed decision: the same @id, the next version, last_updated now.
	list[0].Status, list[0].Justification, list[0].Action = Affected, "", "Update a."
	changed, _ := Export("Maker", "shipward test", product, list, targets, aliases, &again, now.Add(2*time.Hour))
	if changed.ID != doc.ID || changed.Version != 2 || changed.Timestamp != doc.Timestamp || changed.LastUpdated != "2026-11-10T11:00:00Z" {
		t.Errorf("changed input: id %s version %d timestamp %s last_updated %s", changed.ID, changed.Version, changed.Timestamp, changed.LastUpdated)
	}
	if third, _ := Export("Maker", "shipward test", product, list, targets, aliases, &changed, now.Add(3*time.Hour)); third.Version != 2 || third.LastUpdated != changed.LastUpdated {
		t.Errorf("unchanged after a change: version %d, last_updated %s", third.Version, third.LastUpdated)
	}

	// Another release is another document, starting at version 1.
	other, _ := Export("Maker", "shipward test", "pkg:generic/App@1.5.0", list, targets, aliases, &changed, now)
	if other.ID == doc.ID || other.Version != 1 {
		t.Errorf("other release: id %s version %d", other.ID, other.Version)
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
