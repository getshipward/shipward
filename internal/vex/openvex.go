package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// OpenVEXContext is the spec version shipward writes.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// Document is an OpenVEX document.
type Document struct {
	Context    string          `json:"@context"`
	ID         string          `json:"@id"`
	Author     string          `json:"author"`
	Timestamp  string          `json:"timestamp"`
	Version    int             `json:"version"`
	Tooling    string          `json:"tooling,omitempty"`
	Statements []OpenStatement `json:"statements"`
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
	ID            string      `json:"@id"`
	Subcomponents []Component `json:"subcomponents,omitempty"`
}

// Component is a subcomponent, named by purl.
type Component struct {
	ID string `json:"@id"`
}

// Export builds the OpenVEX document for a product. productID is the product's IRI (shipward uses the SBOM's BOM-Link);
// targets are the product's component purls (with versions), so a statement for every version is written for the
// versions the product ships. aliases gives each advisory's other IDs. The document is deterministic: its timestamp
// is the newest decision date and its @id a hash of the content, so an unchanged vex.yaml gives an unchanged file.
func Export(author, tooling, productID string, list []Statement, targets []string, aliases map[string][]string) (Document, error) {
	var out []OpenStatement
	newest := ""
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
		ts := s.Date + "T00:00:00Z"
		if s.Date > newest {
			newest = s.Date
		}
		out = append(out, OpenStatement{
			Vulnerability:   Vulnerability{Name: s.ID, Aliases: aliases[s.ID]},
			Timestamp:       ts,
			Products:        []Product{{ID: productID, Subcomponents: sub}},
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
	if newest == "" {
		newest = time.Now().UTC().Format(time.DateOnly)
	}
	doc := Document{Context: OpenVEXContext, Author: author, Timestamp: newest + "T00:00:00Z", Version: 1, Tooling: tooling,
		Statements: out}
	if doc.Statements == nil {
		doc.Statements = []OpenStatement{}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return Document{}, err
	}
	h := sha256.Sum256(body)
	doc.ID = fmt.Sprintf("urn:shipward:vex:%s", hex.EncodeToString(h[:16]))
	return doc, nil
}
