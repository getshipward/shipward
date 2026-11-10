package advisory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func full() Advisory {
	return Advisory{ID: "CVE-2026-1234", Aliases: []string{"GHSA-abcd-efgh-ijkl", "CVE-2026-9999"}, Title: "Login bypass",
		Product: "Example Game", Manufacturer: "Example s.p.", Namespace: "https://example.com", Contact: "security@example.com",
		Affected: []string{"1.3.0", "1.3.1"}, FixedIn: "1.4.0", Component: "pkg:nuget/Lib@2.0.0",
		Description: "The login accepts an empty token.", Impact: "Anyone can play as another user.", Severity: "high",
		CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", References: []string{"https://example.org/GHSA-abcd-efgh-ijkl"},
		Date: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC), Tool: "shipward test"}
}

func TestMarkdown(t *testing.T) {
	md, err := Markdown(full())
	if err != nil {
		t.Fatal(err)
	}
	// The five items of Annex I Part II(4): description, product identification, impact, severity, remediation.
	for _, want := range []string{"# Security advisory: Login bypass", "CVE-2026-1234, GHSA-abcd-efgh-ijkl, CVE-2026-9999",
		"| Affected versions | 1.3.0, 1.3.1 |", "| Fixed in | 1.4.0 |", "| Severity | high (`CVSS:3.1/", "empty token",
		"Anyone can play", "Update Example Game to version 1.4.0 or later.", "- https://example.org/GHSA", "Questions: security@example.com.",
		"Draft written by shipward test", "it is not legal advice", "keep it out of public repositories",
		"security risks of publishing to\noutweigh the benefits"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}

	md, err = Markdown(Advisory{ID: "EXAMPLE-2026-001", Product: "Example Game", Tool: "shipward test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Security advisory: EXAMPLE-2026-001 in Example Game", "TODO: the versions that have the flaw",
		"TODO: the version with the security update", "TODO: a description", "TODO: what an attacker can do", "TODO: clear steps",
		"Questions: TODO: a contact.", "Draft written by shipward test"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("minimal markdown lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(string(md), "Affected component") || strings.Contains(string(md), "More information") {
		t.Errorf("minimal markdown has empty sections:\n%s", md)
	}
}

func TestCSAF(t *testing.T) {
	body, err := CSAF(full())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Document struct {
			Category, CSAFVersion string
			Publisher             struct{ Category, Name, Namespace string }
			Notes                 []struct{ Category, Text string }
			References            []struct{ URL string }
			AggregateSeverity     struct{ Text string } `json:"aggregate_severity"`
			Tracking              struct {
				ID, Status, Version string
				RevisionHistory     []struct{ Number string } `json:"revision_history"`
			}
		}
		ProductTree struct {
			Branches []struct {
				Name     string
				Branches []struct {
					Name     string
					Branches []struct {
						Name    string
						Product struct {
							ProductID string `json:"product_id"`
						}
					}
				}
			}
		} `json:"product_tree"`
		Vulnerabilities []struct {
			CVE string
			IDs []struct {
				SystemName string `json:"system_name"`
				Text       string
			} `json:"ids"`
			ProductStatus struct {
				KnownAffected []string `json:"known_affected"`
				Fixed         []string
			} `json:"product_status"`
			Remediations []struct {
				Category, Details string
				ProductIDs        []string `json:"product_ids"`
			}
			Threats []struct{ Category, Details string }
		}
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"category": "csaf_security_advisory"`) || !strings.Contains(string(body), `"csaf_version": "2.0"`) {
		t.Errorf("not a CSAF 2.0 security advisory:\n%s", body)
	}
	d := doc.Document
	if d.Publisher.Category != "vendor" || d.Publisher.Namespace != "https://example.com" || d.Tracking.Status != "draft" ||
		d.Tracking.Version != "0" || len(d.Tracking.RevisionHistory) != 1 || d.Tracking.RevisionHistory[0].Number != "0" ||
		d.AggregateSeverity.Text != "high" || len(d.References) == 0 {
		t.Errorf("document = %+v", d)
	}
	cats := map[string]bool{}
	for _, n := range d.Notes {
		cats[n.Category] = true
	}
	if !cats["summary"] || !cats["legal_disclaimer"] {
		t.Errorf("notes = %+v", d.Notes)
	}
	// Every product ID in the status and the remediation is defined in the product tree.
	defined := map[string]bool{}
	for _, v := range doc.ProductTree.Branches[0].Branches[0].Branches {
		defined[v.Product.ProductID] = true
	}
	v := doc.Vulnerabilities[0]
	if v.CVE != "CVE-2026-1234" || len(v.IDs) != 2 || v.IDs[0].SystemName != "GitHub Security Advisory" || v.IDs[1].Text != "CVE-2026-9999" {
		t.Errorf("ids = %q %+v", v.CVE, v.IDs)
	}
	if len(v.ProductStatus.KnownAffected) != 2 || len(v.ProductStatus.Fixed) != 1 || len(defined) != 3 {
		t.Errorf("status = %+v, tree = %v", v.ProductStatus, defined)
	}
	for _, id := range append(append(v.ProductStatus.KnownAffected, v.ProductStatus.Fixed...), v.Remediations[0].ProductIDs...) {
		if !defined[id] {
			t.Errorf("product ID %q is not in the product tree", id)
		}
	}
	if v.Remediations[0].Category != "vendor_fix" || !strings.Contains(v.Remediations[0].Details, "1.4.0") || v.Threats[0].Category != "impact" {
		t.Errorf("vulnerability = %+v", v)
	}

	if _, err := CSAF(Advisory{ID: "X-1", Product: "P", Tool: "t"}); err == nil ||
		!strings.Contains(err.Error(), "--affected") || !strings.Contains(err.Error(), "--fixed-in") || !strings.Contains(err.Error(), "manufacturer.url") {
		t.Errorf("incomplete CSAF: %v", err)
	}
}

func TestCSAFDistinctVersions(t *testing.T) {
	a := full()
	a.Affected = []string{"1.3.0", "1.4.0"}
	if _, err := CSAF(a); err == nil || !strings.Contains(err.Error(), "both affected and fixed") {
		t.Errorf("fixed version also affected: %v", err)
	}
	a.Affected = []string{"1 0", "1-0"}
	if _, err := CSAF(a); err == nil || !strings.Contains(err.Error(), "the same product") {
		t.Errorf("colliding versions: %v", err)
	}
}

func TestFileName(t *testing.T) {
	if got := FileName("GHSA-abcd/../x y"); got != "GHSA-abcd-..-x-y" && strings.Contains(got, "/") {
		t.Errorf("FileName = %q", got)
	}
	if strings.ContainsAny(FileName("a/b\\c"), `/\`) || FileName("///") != "advisory" || FileName("..") != "advisory" || FileName(".hidden") != "hidden" {
		t.Errorf("FileName unsafe: %q %q", FileName("a/b\\c"), FileName("///"))
	}
}
