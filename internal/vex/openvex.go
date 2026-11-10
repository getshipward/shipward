package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OpenVEXContext is the spec version shipward writes.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// Document is an OpenVEX document.
type Document struct {
	Context     string          `json:"@context"`
	ID          string          `json:"@id"`
	Author      string          `json:"author"`
	Timestamp   string          `json:"timestamp"`
	LastUpdated string          `json:"last_updated,omitempty"`
	Version     int             `json:"version"`
	Tooling     string          `json:"tooling,omitempty"`
	Statements  []OpenStatement `json:"statements"`
}

// OpenStatement is one OpenVEX statement.
type OpenStatement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Timestamp       string        `json:"timestamp,omitempty"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

// Vulnerability names an advisory.
type Vulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Product is the product a statement is about, with the component (subcomponent) that carries the advisory.
type Product struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Subcomponents []Component       `json:"subcomponents,omitempty"`
}

// Component is a subcomponent, named by purl.
type Component struct {
	ID string `json:"@id"`
}

// Export builds the OpenVEX document for a product. productID is the product's IRI: a purl or URL with the product
// version, the same on every run for the same release. targets are the product's component purls (with versions), so
// a statement for every version is written for the versions the product ships. aliases gives each advisory's other
// IDs.
//
// The document's @id comes from productID, so each release has one document that keeps its @id. prev is the
// document written before (nil if none): when it has the same @id, the statements are compared. Unchanged statements
// keep prev's version and times, so an unchanged vex.yaml gives an unchanged file; changed ones get version + 1 and
// last_updated now. A new document has version 1 and the newest decision time as its timestamp.
func Export(author, tooling, productID string, list []Statement, targets []string, aliases map[string][]string, prev *Document, now time.Time) (Document, error) {
	var out []OpenStatement
	var newest time.Time
	for _, s := range list {
		comps := []string{s.Component}
		if hasVersion(s.Component) {
			exact, _ := Keys(s.Component)
			shipped := false
			for _, t := range targets {
				if e, _ := Keys(t); e == exact {
					shipped = true
				}
			}
			if !shipped {
				continue // the product no longer ships this version
			}
		} else {
			comps = nil
			_, want := Keys(s.Component)
			for _, t := range targets {
				if _, a := Keys(t); a == want {
					comps = append(comps, t)
				}
			}
			if len(comps) == 0 {
				continue // the product no longer ships this component
			}
		}
		sort.Strings(comps)
		sub := make([]Component, len(comps))
		for i, c := range comps {
			sub[i] = Component{ID: c}
		}
		t, err := Time(s.Date)
		if err != nil {
			return Document{}, fmt.Errorf("%s %s: %w", s.ID, s.Component, err)
		}
		t = t.UTC()
		if t.After(newest) {
			newest = t
		}
		out = append(out, OpenStatement{
			Vulnerability:   Vulnerability{Name: s.ID, Aliases: aliases[s.ID]},
			Timestamp:       t.Format(time.RFC3339),
			Products:        []Product{{ID: productID, Identifiers: identifiers(productID), Subcomponents: sub}},
			Status:          s.Status,
			Justification:   s.Justification,
			ImpactStatement: s.Impact,
			ActionStatement: s.Action,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Vulnerability.Name != out[j].Vulnerability.Name {
			return out[i].Vulnerability.Name < out[j].Vulnerability.Name
		}
		return out[i].Products[0].Subcomponents[0].ID < out[j].Products[0].Subcomponents[0].ID
	})
	if out == nil {
		out = []OpenStatement{}
	}
	if newest.IsZero() {
		newest = now.UTC()
	}
	h := sha256.Sum256([]byte(productID))
	doc := Document{Context: OpenVEXContext, ID: "urn:shipward:vex:" + hex.EncodeToString(h[:16]), Author: author,
		Timestamp: newest.Format(time.RFC3339), Version: 1, Tooling: tooling, Statements: out}
	if prev != nil && prev.ID == doc.ID && prev.Version > 0 {
		same, err := sameStatements(prev.Statements, out)
		if err != nil {
			return Document{}, err
		}
		doc.Timestamp, doc.LastUpdated, doc.Version = prev.Timestamp, prev.LastUpdated, prev.Version
		if !same {
			doc.Version++
			doc.LastUpdated = now.UTC().Format(time.RFC3339)
		}
	}
	return doc, nil
}

// identifiers repeats a purl product ID under "purl", where scanners look for it.
func identifiers(productID string) map[string]string {
	if strings.HasPrefix(productID, "pkg:") {
		return map[string]string{"purl": productID}
	}
	return nil
}

func sameStatements(a, b []OpenStatement) (bool, error) {
	ja, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	jb, err := json.Marshal(b)
	return err == nil && string(ja) == string(jb), err
}
