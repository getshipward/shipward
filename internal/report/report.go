// Package report keeps the cases a manufacturer must report under the EU Cyber Resilience Act, Article 14: an actively
// exploited vulnerability or a severe incident. Each case is a folder with report.yaml (the facts and the times) and
// Markdown drafts of each report. shipward computes the deadlines; a person submits the reports on ENISA's single reporting
// platform, which has no API.
package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Types of case.
const (
	Vulnerability = "vulnerability" // Art. 14(1), (2)
	Incident      = "incident"      // Art. 14(3), (4)
)

// Stages, in order.
const (
	EarlyWarning = "early-warning"
	Notification = "notification"
	Final        = "final"
	Users        = "users"
)

// Stages lists the stages a case goes through.
var Stages = []string{EarlyWarning, Notification, Final, Users}

// Case is the content of report.yaml.
type Case struct {
	Type  string `yaml:"type"`
	Title string `yaml:"title"`
	// Aware is when the manufacturer became aware of the exploited vulnerability or the severe incident: the 24- and
	// 72-hour clocks start here.
	Aware time.Time `yaml:"aware"`

	Advisories []string `yaml:"advisories,omitempty"` // GHSA, CVE, ... (vulnerability)
	Components []string `yaml:"components,omitempty"` // affected components, as purls
	Versions   []string `yaml:"versions,omitempty"`   // affected product versions
	// MemberStates where the product is made available, or ["EU"].
	MemberStates []string `yaml:"member_states,omitempty"`
	// Malicious says whether the incident is suspected to be caused by unlawful or malicious acts: yes, no, unknown.
	Malicious string `yaml:"malicious,omitempty"`
	// Sensitivity is how sensitive the manufacturer considers the information (for example TLP:AMBER).
	Sensitivity string `yaml:"sensitivity,omitempty"`

	MeasuresTaken []string `yaml:"measures_taken,omitempty"` // corrective or mitigating measures taken
	UserMeasures  []string `yaml:"user_measures,omitempty"`  // measures users can take
	// FixAvailable is when a corrective or mitigating measure became available: the final report of a vulnerability
	// is due 14 days later.
	FixAvailable *time.Time `yaml:"fix_available,omitempty"`

	// Submitted records when each stage was sent (reports on the platform; users: the notice to users).
	Submitted map[string]time.Time `yaml:"submitted,omitempty"`
	Notes     string               `yaml:"notes,omitempty"`
}

// Header is written at the top of report.yaml.
const Header = `# A case to report under the EU Cyber Resilience Act, Article 14 (shipward report). It describes a vulnerability or an
# incident that may not be fixed or public yet: keep it out of public repositories. Times are RFC 3339.
`

// Validate checks a case.
func (c Case) Validate() error {
	var errs []error
	if c.Type != Vulnerability && c.Type != Incident {
		errs = append(errs, fmt.Errorf("type %q is not %s or %s", c.Type, Vulnerability, Incident))
	}
	if c.Title == "" {
		errs = append(errs, errors.New("title is required"))
	}
	if c.Aware.IsZero() {
		errs = append(errs, errors.New("aware is required"))
	}
	switch c.Malicious {
	case "", "yes", "no", "unknown":
	default:
		errs = append(errs, fmt.Errorf("malicious %q is not yes, no or unknown", c.Malicious))
	}
	for stage := range c.Submitted {
		if !contains(Stages, stage) {
			errs = append(errs, fmt.Errorf("submitted: unknown stage %q", stage))
		}
	}
	return errors.Join(errs...)
}

// Deadline is one stage's due time. Due is zero when it cannot be known yet (the final report of a vulnerability
// before a fix exists; the final report of an incident before the notification is sent; the users' notice, which
// has no fixed time).
type Deadline struct {
	Stage string
	Due   time.Time
	Done  time.Time
	Why   string // the rule, for people
}

// Deadlines returns the four stages with their due times (CRA Art. 14(2), (4), (8)).
func (c Case) Deadlines() []Deadline {
	ds := []Deadline{
		{Stage: EarlyWarning, Due: c.Aware.Add(24 * time.Hour), Why: "24 hours after becoming aware"},
		{Stage: Notification, Due: c.Aware.Add(72 * time.Hour), Why: "72 hours after becoming aware"},
	}
	final := Deadline{Stage: Final}
	if c.Type == Vulnerability {
		final.Why = "14 days after a corrective or mitigating measure is available"
		if c.FixAvailable != nil {
			final.Due = c.FixAvailable.Add(14 * 24 * time.Hour)
		}
	} else {
		final.Why = "one month after the incident notification was submitted"
		if n, ok := c.Submitted[Notification]; ok {
			final.Due = n.AddDate(0, 1, 0)
		}
	}
	ds = append(ds, final, Deadline{Stage: Users, Why: "inform impacted users in a timely manner"})
	for i := range ds {
		ds[i].Done = c.Submitted[ds[i].Stage]
	}
	return ds
}

// Next returns the first stage not done yet, or false when all are.
func (c Case) Next() (Deadline, bool) {
	for _, d := range c.Deadlines() {
		if d.Done.IsZero() {
			return d, true
		}
	}
	return Deadline{}, false
}

// Load reads a case folder's report.yaml.
func Load(dir string) (*Case, error) {
	data, err := os.ReadFile(filepath.Join(dir, "report.yaml"))
	if err != nil {
		return nil, err
	}
	var c Case
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return &c, nil
}

// Save writes report.yaml.
func Save(dir string, c *Case) error {
	if err := c.Validate(); err != nil {
		return err
	}
	body, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append([]byte(Header), body...)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, "report.yaml"))
}

// List returns the case folders under dir, oldest first.
func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, e.Name(), "report.yaml")); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slug makes a folder name from the date the case started and its title.
func Slug(aware time.Time, title string) string {
	s := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(title), "-"), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		s = "case"
	}
	return aware.UTC().Format("2006-01-02") + "-" + s
}

// ParseTime reads a time as RFC 3339, or as "2006-01-02 15:04" in the given location.
func ParseTime(s string, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04", s, loc); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("time %q is neither RFC 3339 (2026-11-06T14:00:00+01:00) nor \"2026-11-06 14:00\"", s)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
