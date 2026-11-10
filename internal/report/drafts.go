package report

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/getshipward/shipward/internal/config"
)

//go:embed templates/*.tmpl
var templates embed.FS

// draftFiles maps each stage to its draft.
var draftFiles = map[string]string{
	EarlyWarning: "early-warning.md",
	Notification: "notification.md",
	Final:        "final.md",
	Users:        "users.md",
	Intermediate: "intermediate.md",
}

// DraftFile returns the file name of a stage's draft.
func DraftFile(stage string) string { return draftFiles[stage] }

type draftData struct {
	ID           string
	Case         *Case
	Product      config.Product
	Manufacturer config.Manufacturer
	CSIRT        string
	Contact      string
	IsIncident   bool
	Due          struct{ EarlyWarning, Notification, Final time.Time }
	FinalLatest  bool   // Due.Final is the latest possible time (incident, notification not recorded)
	FinalHint    string // an extra line about the final report's deadline, or empty
	Note         string
	// For ENISA's form: the CVE and EUVD IDs among the advisories, and whether the support period had ended when the
	// manufacturer became aware.
	CVE, EUVD    []string
	EndOfSupport string
	Glossary     string
}

// Glossary names the version of ENISA's field list the drafts follow.
const Glossary = "ENISA's CRA SRP Glossary, version 1.6 (21 October 2026)"

// endOfSupport answers field 11 from product.support_until (YYYY-MM): has the support period ended at aware?
func endOfSupport(until string, aware time.Time) string {
	t, err := time.Parse("2006-01", until)
	if err != nil {
		return ""
	}
	end := t.AddDate(0, 1, 0) // the period runs to the end of that month
	if aware.Before(end) {
		return "No (support until the end of " + t.Format("January 2006") + ")"
	}
	return "Yes (support ended at the end of " + t.Format("January 2006") + ")"
}

// WriteDrafts writes the drafts of a case. Existing drafts are kept unless force is set (report.yaml holds the facts;
// a draft may have been edited). It returns the files it wrote.
func WriteDrafts(dir, id string, c *Case, cfg *config.Config, force bool, loc *time.Location, tool string) ([]string, error) {
	d := draftData{ID: id, Case: c, Product: cfg.Product, Manufacturer: cfg.Manufacturer, CSIRT: cfg.Reports.CSIRT,
		Contact: strings.TrimPrefix(cfg.Security.Contact, "mailto:"), IsIncident: c.Type == Incident,
		Note: fmt.Sprintf("Draft written by %s. It follows CRA Article 14 and helps you prepare; it is not legal advice. "+
			"It describes something that may not be public yet: keep it private.", tool)}
	if d.Contact == "" {
		d.Contact = "TODO: a contact"
	}
	for _, a := range c.Advisories {
		switch {
		case strings.HasPrefix(a, "CVE-"):
			d.CVE = append(d.CVE, a)
		case strings.HasPrefix(a, "EUVD-"):
			d.EUVD = append(d.EUVD, a)
		}
	}
	d.EndOfSupport = endOfSupport(cfg.Product.SupportUntil, c.Aware)
	d.Glossary = Glossary
	for _, dl := range c.Deadlines() {
		switch dl.Stage {
		case EarlyWarning:
			d.Due.EarlyWarning = dl.Due
		case Notification:
			d.Due.Notification = dl.Due
		case Final:
			d.Due.Final, d.FinalLatest, d.FinalHint = dl.Due, dl.Latest, dl.Hint
		}
	}
	funcs := template.FuncMap{
		"join": strings.Join,
		// sentence ends a sentence with a full stop, unless the text already ends with one ("..., s.p.").
		"sentence": func(s string) string {
			if strings.HasSuffix(s, ".") {
				return s
			}
			return s + "."
		},
		// states names the Member States; "EU" means all of them.
		"states": func(list []string) string {
			if len(list) == 1 && strings.EqualFold(list[0], "EU") {
				return "All EU Member States"
			}
			return strings.Join(list, ", ")
		},
		"when": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				return When(v, loc)
			case *time.Time:
				if v == nil {
					return "not yet"
				}
				return When(*v, loc)
			}
			return fmt.Sprint(t)
		},
		// utc writes a time as ENISA's form asks for it, e.g. "2026-11-06 13:00 UTC".
		"utc": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" },
		// field writes a value for one of the form's fields, or the fallback when it is empty, and says when the
		// value is longer than the form takes.
		"field": func(value string, max int, fallback string) string {
			if strings.TrimSpace(value) == "" {
				return fallback
			}
			if n := utf8.RuneCountInString(value); max > 0 && n > max {
				return fmt.Sprintf("%s\n\n**Too long for the form: %d characters, the field takes %d.**", value, n, max)
			}
			return value
		},
		// items writes a bullet list, or "" when there are none.
		"items": func(items []string) string {
			if len(items) == 0 {
				return ""
			}
			return "- " + strings.Join(items, "\n- ")
		},
		// lines joins items with "; " for a one-line field.
		"lines": func(items []string) string { return strings.Join(items, "; ") },
		// list writes items as a bullet list, or the fallback text when there are none.
		"list": func(items []string, fallback string) string {
			if len(items) == 0 {
				return fallback
			}
			return "\n- " + strings.Join(items, "\n- ")
		},
	}
	var written []string
	for _, stage := range Stages {
		if stage == Intermediate && c.IntermediateDue == nil {
			continue // only when the CSIRT asked for one
		}
		path := filepath.Join(dir, draftFiles[stage])
		if _, err := os.Stat(path); err == nil && !force {
			continue
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return written, err
		}
		name := strings.TrimSuffix(draftFiles[stage], ".md") + ".md.tmpl"
		tmpl, err := template.New(name).Funcs(funcs).Option("missingkey=error").ParseFS(templates, "templates/"+name)
		if err != nil {
			return written, err
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, d); err != nil {
			return written, fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// When formats a time for people: in loc, with the zone, e.g. "Fri 6 Nov 2026 15:00 CET".
func When(t time.Time, loc *time.Location) string {
	return t.In(loc).Format("Mon 2 Jan 2006 15:04 MST")
}
