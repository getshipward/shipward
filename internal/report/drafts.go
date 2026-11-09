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
	Note         string
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
	for _, dl := range c.Deadlines() {
		switch dl.Stage {
		case EarlyWarning:
			d.Due.EarlyWarning = dl.Due
		case Notification:
			d.Due.Notification = dl.Due
		case Final:
			d.Due.Final = dl.Due
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
