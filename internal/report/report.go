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

// Stages.
const (
	EarlyWarning = "early-warning"
	Notification = "notification"
	Final        = "final"
	Users        = "users"        // the notice to users (Art. 14(8)): in parallel with the reports, from awareness
	Intermediate = "intermediate" // only when the CSIRT asks for it (Art. 14(6))
)

// Stages lists every stage a case can have.
var Stages = []string{EarlyWarning, Notification, Final, Users, Intermediate}

// Skippable lists the reports that need not be sent when "the relevant information has already been provided"
// (Art. 14(2)(b), (c), (4)(b), (c)).
var Skippable = []string{Notification, Final}

// Case is the content of report.yaml.
type Case struct {
	Type  string `yaml:"type"`
	Title string `yaml:"title"`
	// Zone is the time zone of the case (IANA, Europe/Ljubljana): times without an offset are read in it, and one month
	// is counted in it. Empty: the computer's zone for times without an offset, each time's own offset for months.
	Zone string `yaml:"zone,omitempty"`
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

	// IntermediateDue is set when the CSIRT asked for an intermediate report (Art. 14(6)): by when.
	IntermediateDue *time.Time `yaml:"intermediate_due,omitempty"`

	// Submitted records when each stage was sent (reports on the platform; users: the notice to users).
	Submitted map[string]time.Time `yaml:"submitted,omitempty"`
	// Skipped gives the reason for a report that was not sent because its information had already been provided. The
	// stage is in Submitted too, with the time this was decided.
	Skipped map[string]string `yaml:"skipped,omitempty"`
	Notes   string            `yaml:"notes,omitempty"`
}

// Header is written at the top of report.yaml.
const Header = `# A case to report under the EU Cyber Resilience Act, Article 14 (shipward report). It describes a vulnerability or an
# incident that may not be fixed or public yet: keep it out of public repositories. Times are RFC 3339; a time without an
# offset (2026-11-06 14:00) is in the case's zone (or this computer's, when zone is empty).
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
	if c.Zone != "" {
		if _, err := time.LoadLocation(c.Zone); err != nil || c.Zone == "Local" {
			errs = append(errs, fmt.Errorf("zone %q is not a time zone name (Europe/Ljubljana)", c.Zone))
		}
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
	if c.FixAvailable != nil && c.Type == Incident {
		errs = append(errs, errors.New("fix_available is for a vulnerability; an incident's final report is due one month after the notification"))
	}
	if !c.Aware.IsZero() {
		for _, stage := range Stages {
			if t, ok := c.Submitted[stage]; ok && t.Before(c.Aware) {
				errs = append(errs, fmt.Errorf("submitted: %s is before aware", stage))
			}
		}
	}
	if c.IntermediateDue != nil && !c.Aware.IsZero() && c.IntermediateDue.Before(c.Aware) {
		errs = append(errs, errors.New("intermediate_due is before aware"))
	}
	if _, ok := c.Submitted[Intermediate]; ok && c.IntermediateDue == nil {
		errs = append(errs, errors.New("submitted: intermediate is recorded, but no CSIRT request (intermediate_due)"))
	}
	for stage, why := range c.Skipped {
		switch {
		case !contains(Skippable, stage):
			errs = append(errs, fmt.Errorf("skipped: %s cannot be skipped (only %s)", stage, strings.Join(Skippable, ", ")))
		case strings.TrimSpace(why) == "":
			errs = append(errs, fmt.Errorf("skipped: %s needs a reason", stage))
		}
		if _, ok := c.Submitted[stage]; !ok {
			errs = append(errs, fmt.Errorf("skipped: %s is not in submitted", stage))
		}
	}
	errs = append(errs, c.checkOrder()...)
	return errors.Join(errs...)
}

// Deadline is one stage's due time. Due is zero when it cannot be known yet (the final report of a vulnerability
// before a fix exists; the users' notice, which has no fixed time).
type Deadline struct {
	Stage string
	Due   time.Time
	Done  time.Time
	Why   string // the rule, for people
	// Latest is set when Due is the latest possible time, computed from an earlier deadline because the real start is
	// not recorded yet (an incident's final report before the notification is recorded).
	Latest bool
	// Hint is an extra line for people, or empty.
	Hint string
	// UndueDelay is set for the reports the law asks for "without undue delay": Due is only the outer limit.
	UndueDelay bool
	// Skipped is the reason when the report was not sent because its information had already been provided.
	Skipped string
}

// Deadlines returns the stages with their due times (CRA Art. 14(2), (4), (6), (8)): early warning, notification,
// final report, users' notice, and the intermediate report when the CSIRT asked for one.
func (c Case) Deadlines() []Deadline {
	notification := c.Aware.Add(72 * time.Hour)
	ds := []Deadline{
		{Stage: EarlyWarning, Due: c.Aware.Add(24 * time.Hour), Why: "24 hours after becoming aware", UndueDelay: true},
		{Stage: Notification, Due: notification, Why: "72 hours after becoming aware", UndueDelay: true},
	}
	final := Deadline{Stage: Final}
	if c.Type == Vulnerability {
		final.Why = "14 days after a corrective or mitigating measure is available"
		if c.FixAvailable != nil {
			final.Due = c.FixAvailable.Add(14 * 24 * time.Hour)
			switch {
			case final.Due.Before(c.Aware):
				// The 14 days ended before the manufacturer became aware (the flaw was fixed in a newer release long
				// ago). The law gives no date for this; ask for the final report together with the notification.
				final.Due = notification
				final.Hint = "the 14 days after the fix ended before you became aware: send the final report with the notification"
			case !final.Due.After(notification):
				final.Hint = "the 14 days after the fix end before the notification is due: send the notification and the final report together by then"
			}
		}
	} else {
		final.Why = "one month after the incident notification was submitted"
		// One month is counted in the case's zone, so the result is the same on every computer.
		if n, ok := c.Submitted[Notification]; ok {
			final.Due = AddMonth(c.in(n))
		} else {
			// Not recorded yet: the notification is due 72 hours after awareness at the latest.
			final.Due, final.Latest = AddMonth(c.in(notification)), true
			final.Hint = "one month after the notification's deadline; it moves earlier when you record the notification"
		}
	}
	ds = append(ds, final, Deadline{Stage: Users, Why: "inform impacted users in a timely manner, in parallel with the reports"})
	if c.IntermediateDue != nil {
		ds = append(ds, Deadline{Stage: Intermediate, Due: *c.IntermediateDue, Why: "the CSIRT asked for an intermediate report"})
	}
	for i := range ds {
		ds[i].Done = c.Submitted[ds[i].Stage]
		ds[i].Skipped = c.Skipped[ds[i].Stage]
	}
	return ds
}

// Deadline returns one stage's deadline, or false when the case does not have that stage.
func (c Case) Deadline(stage string) (Deadline, bool) {
	for _, d := range c.Deadlines() {
		if d.Stage == stage {
			return d, true
		}
	}
	return Deadline{}, false
}

// Closed reports whether every stage of the case is done.
func (c Case) Closed() bool {
	for _, d := range c.Deadlines() {
		if d.Done.IsZero() {
			return false
		}
	}
	return true
}

// AddMonth adds one calendar month and keeps the clock time. When the day does not exist in the next month (31 January),
// it gives the last day of that month (28 or 29 February), as Regulation (EEC, Euratom) No 1182/71, Article 3(2)(c),
// counts periods in months. The legal end is the end of that day, and a weekend or public holiday can move it later;
// keeping the clock time stays on the safe side.
func AddMonth(t time.Time) time.Time {
	y, m, d := t.Date()
	first := time.Date(y, m+1, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	if last := first.AddDate(0, 1, -1).Day(); d > last {
		d = last
	}
	return time.Date(first.Year(), first.Month(), d, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
}

// reports are the stages that follow each other (Art. 14(2), (4)). The users' notice (Art. 14(8)) has no place in
// that order.
var reports = []string{EarlyWarning, Notification, Final}

// Previous returns the report that must be sent before stage, or "" (the early warning and the users' notice).
func Previous(stage string) string {
	for i := 1; i < len(reports); i++ {
		if reports[i] == stage {
			return reports[i-1]
		}
	}
	return ""
}

// checkOrder checks that no report is recorded before the one it follows.
func (c Case) checkOrder() []error {
	var errs []error
	for i := 1; i < len(reports); i++ {
		t, ok := c.Submitted[reports[i]]
		if !ok {
			continue
		}
		prev, okPrev := c.Submitted[reports[i-1]]
		switch {
		case !okPrev:
			errs = append(errs, fmt.Errorf("submitted: %s is recorded, %s is not", reports[i], reports[i-1]))
		case t.Before(prev):
			errs = append(errs, fmt.Errorf("submitted: %s is before %s", reports[i], reports[i-1]))
		}
	}
	return errs
}

// Next returns the next report to send to the CSIRT: the first open one of early warning, notification, an
// intermediate report the CSIRT asked for, and the final report; or false when all are done. The users' notice runs in
// parallel and is not part of this order.
func (c Case) Next() (Deadline, bool) {
	for _, stage := range []string{EarlyWarning, Notification, Intermediate, Final} {
		if d, ok := c.Deadline(stage); ok && d.Done.IsZero() {
			return d, true
		}
	}
	return Deadline{}, false
}

// Load reads a case folder's report.yaml. A time without a zone offset ("2026-11-06 14:00") is in the case's zone, or
// in loc when the case has none, as on the command line.
func Load(dir string, loc *time.Location) (*Case, error) {
	data, err := os.ReadFile(filepath.Join(dir, "report.yaml"))
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if z := zoneOf(&doc); z != "" {
		if zl, err := time.LoadLocation(z); err == nil && z != "Local" {
			loc = zl
		}
	}
	if err := localTimes(&doc, loc); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	var c Case
	if err := doc.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	c.normalise()
	return &c, nil
}

// zoneOf returns the zone key of report.yaml, or "".
func zoneOf(doc *yaml.Node) string {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return ""
	}
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		if m[i].Value == "zone" && m[i+1].Kind == yaml.ScalarNode {
			return m[i+1].Value
		}
	}
	return ""
}

// localTimes reads the times in report.yaml (aware, fix_available, each value under submitted) with ParseTime, so a
// time without an offset is in loc. YAML alone would read it as UTC.
func localTimes(doc *yaml.Node, loc *time.Location) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil // empty or not a mapping: Decode reports it
	}
	fix := func(key string, n *yaml.Node) error {
		if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
			return nil
		}
		t, err := ParseTime(n.Value, loc)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		n.Value, n.Tag, n.Style = t.Format(time.RFC3339Nano), "!!timestamp", 0
		return nil
	}
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		key, val := m[i].Value, m[i+1]
		switch key {
		case "aware", "fix_available", "intermediate_due":
			if err := fix(key, val); err != nil {
				return err
			}
		case "submitted":
			if val.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(val.Content); j += 2 {
				if err := fix("submitted: "+val.Content[j].Value, val.Content[j+1]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Save writes report.yaml.
func Save(dir string, c *Case) error {
	if err := c.Validate(); err != nil {
		return err
	}
	c.normalise()
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

// localLayouts are the forms of a time without a zone offset that ParseTime reads in the given location.
var localLayouts = []string{"2006-01-02 15:04", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02T15:04:05"}

// ParseTime reads a time as RFC 3339, or as "2006-01-02 15:04" (seconds and a T in place of the space are allowed)
// in the given location.
func ParseTime(s string, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	for _, layout := range localLayouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
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
