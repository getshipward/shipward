// Package vex keeps the maker's decisions about advisories (VEX: Vulnerability Exploitability eXchange) in vex.yaml,
// a file in the maker's repository, and writes them as an OpenVEX document (https://openvex.dev, spec v0.2.0). The
// words for status and justification are OpenVEX's.
package vex

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	packageurl "github.com/anchore/packageurl-go"
	"go.yaml.in/yaml/v3"
)

// Statuses (OpenVEX).
const (
	NotAffected        = "not_affected"
	Affected           = "affected"
	Fixed              = "fixed"
	UnderInvestigation = "under_investigation"
)

// Statuses lists the allowed statuses.
var Statuses = []string{NotAffected, Affected, Fixed, UnderInvestigation}

// Justifications are OpenVEX's reasons for not_affected.
var Justifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// Header is written at the top of a new vex.yaml.
const Header = `# Decisions about advisories that name a component of this product (VEX). cra scan shows them next to each
# advisory; cra triage export writes them as OpenVEX. Add or change entries with cra triage set, or by hand.
# status: not_affected (needs justification or impact), affected (needs action), fixed, under_investigation.
# component: a purl with @version, or without it for every version.
`

// Statement is one decision.
type Statement struct {
	ID            string `yaml:"id"`        // the advisory ID or one of its aliases (GHSA-..., CVE-...)
	Component     string `yaml:"component"` // purl, with or without @version
	Status        string `yaml:"status"`
	Justification string `yaml:"justification,omitempty"`
	Impact        string `yaml:"impact,omitempty"` // why it does not affect the product (not_affected)
	Action        string `yaml:"action,omitempty"` // what users should do (affected)
	By            string `yaml:"by,omitempty"`
	Date          string `yaml:"date"` // YYYY-MM-DD
}

// Validate checks one statement against the OpenVEX rules.
func (s Statement) Validate() error {
	var errs []error
	if s.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if _, err := packageurl.FromString(s.Component); err != nil {
		errs = append(errs, fmt.Errorf("component %q is not a purl", s.Component))
	}
	if !contains(Statuses, s.Status) {
		errs = append(errs, fmt.Errorf("status %q is not one of %s", s.Status, strings.Join(Statuses, ", ")))
	}
	if s.Justification != "" && !contains(Justifications, s.Justification) {
		errs = append(errs, fmt.Errorf("justification %q is not one of %s", s.Justification, strings.Join(Justifications, ", ")))
	}
	switch s.Status {
	case NotAffected:
		if s.Justification == "" && s.Impact == "" {
			errs = append(errs, errors.New("not_affected needs a justification or an impact statement"))
		}
	case Affected:
		if s.Action == "" {
			errs = append(errs, errors.New("affected needs an action statement (what users should do)"))
		}
	}
	if s.Status != NotAffected && s.Justification != "" {
		errs = append(errs, errors.New("a justification is only for not_affected"))
	}
	if _, err := time.Parse(time.DateOnly, s.Date); err != nil {
		errs = append(errs, fmt.Errorf("date %q is not YYYY-MM-DD", s.Date))
	}
	return errors.Join(errs...)
}

// Load reads vex.yaml. A missing file returns no statements and no error.
func Load(path string) ([]Statement, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Statement
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	for i, s := range list {
		if err := s.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: entry %d (%s %s): %w", path, i, s.ID, s.Component, err))
		}
	}
	return list, errors.Join(errs...)
}

// Set adds a statement to vex.yaml, or replaces the one with the same id and component. Comments in the file are kept.
func Set(path string, s Statement) error {
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var doc yaml.Node
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	var seq *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.SequenceNode {
		seq = doc.Content[0]
	} else if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		seq = &yaml.Node{Kind: yaml.SequenceNode}
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{seq}, HeadComment: strings.TrimSuffix(Header, "\n")}
	} else {
		return fmt.Errorf("%s: expected a list of decisions", path)
	}

	var node yaml.Node
	if err := node.Encode(s); err != nil {
		return err
	}
	replaced := false
	for i, item := range seq.Content {
		var old Statement
		if item.Decode(&old) == nil && old.ID == s.ID && old.Component == s.Component {
			node.HeadComment = item.HeadComment
			seq.Content[i] = &node
			replaced = true
			break
		}
	}
	if !replaced {
		seq.Content = append(seq.Content, &node)
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return writeAtomic(path, out)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vex-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Find returns the statement for an advisory (by ID or alias) on a component purl. One for this version wins over one
// for every version.
func Find(list []Statement, ids []string, purl string) *Statement {
	exact, anyVersion := Keys(purl)
	var loose *Statement
	for i := range list {
		s := &list[i]
		if !contains(ids, s.ID) {
			continue
		}
		e, a := Keys(s.Component)
		switch {
		case e == exact && hasVersion(s.Component):
			return s
		case !hasVersion(s.Component) && a == anyVersion && loose == nil:
			loose = s
		}
	}
	return loose
}

// Keys returns a purl without qualifiers and subpath, with and without its version. Names are compared without case
// for NuGet and Composer, whose registries ignore case.
func Keys(s string) (exact, anyVersion string) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return s, s
	}
	p.Qualifiers, p.Subpath = nil, ""
	if p.Type == packageurl.TypeNuget || p.Type == packageurl.TypeComposer {
		p.Namespace, p.Name = strings.ToLower(p.Namespace), strings.ToLower(p.Name)
	}
	exact = p.ToString()
	p.Version = ""
	return exact, p.ToString()
}

func hasVersion(s string) bool {
	p, err := packageurl.FromString(s)
	return err == nil && p.Version != ""
}

// Final reports whether a status closes an advisory (a decision that needs no more work).
func Final(status string) bool { return status == NotAffected || status == Fixed }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// SortStatements orders statements by id, then component, for stable output.
func SortStatements(list []Statement) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].ID != list[j].ID {
			return list[i].ID < list[j].ID
		}
		return list[i].Component < list[j].Component
	})
}
