package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/report"
)

const reportUsage = `usage:
  shipward report [--fail-on overdue]                     open cases: the next report, its deadline, the time left
  shipward report new vulnerability|incident --title T --aware TIME [--advisory ID] [--component PURL] [--version V]
                                                     open a case and write the drafts
  shipward report fixed CASE [--at TIME]                  vulnerability: a corrective or mitigating measure is available
                                                     (starts the 14 days; it may be before you became aware)
  shipward report done CASE STAGE [--at TIME] [--skipped REASON]
                                                     STAGE was submitted: early-warning, notification, final, users,
                                                     intermediate (the reports in this order; not before aware, not
                                                     in the future). --skipped: notification or final not sent, its
                                                     information was already provided (Art. 14(2), (4))
  shipward report intermediate CASE --due TIME            the CSIRT asked for an intermediate report by TIME (Art. 14(6))
  shipward report drafts CASE [--force] [--csaf]          write the drafts again from report.yaml; --csaf also writes the
                                                     users' notice as CSAF 2.0 (users.csaf.json)

TIME is RFC 3339 (2026-11-06T14:00:00+01:00) or "2026-11-06 14:00" in local time (the case's zone in report.yaml,
set by report new); default now. report.yaml reads times without an offset the same way.
Reports go to your CSIRT coordinator through ENISA's single reporting platform; a person submits them there.
`

// stringList is a flag that can be given more than once.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runReport(args []string, stdout, stderr io.Writer) int {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "list":
		return reportList(args, stdout, stderr, time.Now())
	case "new":
		return reportNew(args, stdout, stderr, time.Now())
	case "fixed", "done", "intermediate":
		return reportMark(sub, args, stdout, stderr, time.Now())
	case "drafts":
		return reportDrafts(args, stdout, stderr)
	case "help":
		fmt.Fprint(stdout, reportUsage)
		return 0
	}
	fmt.Fprintf(stderr, "shipward report: unknown command %q\n\n%s", sub, reportUsage)
	return 2
}

func reportList(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	failOn := fs.String("fail-on", "none", "exit 3 when a report is overdue (overdue) or never (none)")
	all := fs.Bool("all", false, "also list closed cases")
	if err := parse(fs, args); err != nil {
		return 2
	}
	if *failOn != "none" && *failOn != "overdue" {
		fmt.Fprintf(stderr, "shipward report: unknown --fail-on %q (none, overdue)\n", *failOn)
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report: %v\n", err)
		return 1
	}
	dir := cfg.Resolve(cfg.Reports.Dir)
	ids, err := report.List(dir)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report: %v\n", err)
		return 1
	}
	overdue, shown := false, 0
	for _, id := range ids {
		c, err := report.Load(filepath.Join(dir, id), time.Local)
		if err != nil {
			fmt.Fprintf(stderr, "shipward report: %v\n", err)
			return 1
		}
		if c.Closed() && !*all {
			continue
		}
		shown++
		fmt.Fprintf(stdout, "%s  %s: %s\n", id, c.Type, c.Title)
		fmt.Fprintf(stdout, "    %-14s %s\n", "aware", report.When(c.Aware, time.Local))
		printStages(stdout, c, id, now)
		for _, d := range c.Deadlines() {
			if d.Done.IsZero() && !d.Due.IsZero() && now.After(d.Due) {
				overdue = true
			}
		}
		fmt.Fprintln(stdout)
	}
	if shown == 0 {
		fmt.Fprintln(stdout, "No open cases. Open one with shipward report new when you learn of an actively exploited vulnerability or a severe incident.")
	}
	if overdue && *failOn == "overdue" {
		return exitFindings
	}
	return 0
}

// displayOrder is the order stages are shown in: the users' notice first, since it runs from awareness in parallel
// with the reports, then the reports in the order they are sent.
var displayOrder = []string{report.Users, report.EarlyWarning, report.Notification, report.Intermediate, report.Final}

func printStages(w io.Writer, c *report.Case, id string, now time.Time) {
	for _, stage := range displayOrder {
		if d, ok := c.Deadline(stage); ok {
			fmt.Fprintf(w, "    %-14s %s\n", d.Stage, stageStatus(d, c, id, now))
		}
	}
}

func stageStatus(d report.Deadline, c *report.Case, id string, now time.Time) string {
	var s string
	switch {
	case d.Skipped != "":
		return fmt.Sprintf("not sent (%s), recorded %s", d.Skipped, report.When(d.Done, time.Local))
	case !d.Done.IsZero():
		return "sent " + report.When(d.Done, time.Local)
	case d.Due.IsZero() && d.Stage == report.Final && c.Type == report.Vulnerability:
		return "at the latest 14 days after a fix is available (shipward report fixed " + id + ")"
	case d.Due.IsZero():
		return "as soon as you can: " + d.Why
	case now.After(d.Due):
		s = fmt.Sprintf("OVERDUE by %s (was due %s)", span(now.Sub(d.Due)), report.When(d.Due, time.Local))
	case d.UndueDelay:
		s = fmt.Sprintf("without undue delay, at the latest %s, in %s", report.When(d.Due, time.Local), span(d.Due.Sub(now)))
	default:
		s = fmt.Sprintf("at the latest %s, in %s", report.When(d.Due, time.Local), span(d.Due.Sub(now)))
	}
	if d.Hint != "" {
		s += "; " + d.Hint
	}
	return s
}

// span writes a duration as days, hours and minutes.
func span(d time.Duration) string {
	d = d.Round(time.Minute)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	h, m := int(d/time.Hour), int((d%time.Hour)/time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func reportNew(args []string, stdout, stderr io.Writer, now time.Time) int {
	if len(args) == 0 || (args[0] != report.Vulnerability && args[0] != report.Incident) {
		fmt.Fprint(stderr, reportUsage)
		return 2
	}
	kind := args[0]
	fs := flag.NewFlagSet("report new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	title := fs.String("title", "", "a short title")
	aware := fs.String("aware", "", "when you became aware of it (default now)")
	malicious := fs.String("malicious", "unknown", "incident: suspected unlawful or malicious acts: yes, no, unknown")
	var advisories, components, versions stringList
	fs.Var(&advisories, "advisory", "advisory ID (GHSA-..., CVE-...); repeat for more")
	fs.Var(&components, "component", "affected component purl; repeat for more")
	fs.Var(&versions, "version", "affected product version; repeat for more")
	if err := parse(fs, args[1:]); err != nil {
		return 2
	}
	if *title == "" {
		fmt.Fprintln(stderr, "shipward report new: --title is required")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report new: %v\n", err)
		return 1
	}
	at := now.Truncate(time.Second)
	if *aware != "" {
		if at, err = report.ParseTime(*aware, time.Local); err != nil {
			fmt.Fprintf(stderr, "shipward report new: %v\n", err)
			return 2
		}
		if at.After(now.Add(time.Minute)) {
			fmt.Fprintln(stderr, "shipward report new: --aware is in the future")
			return 2
		}
	}
	c := &report.Case{Type: kind, Title: *title, Zone: report.LocalZone(), Aware: at, Advisories: advisories, Components: components,
		Versions: versions, MemberStates: cfg.Product.Markets}
	if kind == report.Incident {
		c.Malicious = *malicious
	}
	id := report.Slug(at, *title)
	dir := filepath.Join(cfg.Resolve(cfg.Reports.Dir), id)
	if _, err := os.Stat(dir); err == nil {
		fmt.Fprintf(stderr, "shipward report new: %s exists already\n", dir)
		return 1
	}
	// A new reports folder gets a .gitignore. An existing one is left as it is: in a private repository the person
	// may have deleted the file on purpose to keep the cases.
	reportsDir := cfg.Resolve(cfg.Reports.Dir)
	_, statErr := os.Stat(reportsDir)
	newFolder := errors.Is(statErr, os.ErrNotExist)
	if err := report.Save(dir, c); err != nil {
		fmt.Fprintf(stderr, "shipward report new: %v\n", err)
		return 1
	}
	if _, err := report.WriteDrafts(dir, id, c, cfg, false, time.Local, "shipward "+version); err != nil {
		fmt.Fprintf(stderr, "shipward report new: %v\n", err)
		return 1
	}
	wroteIgnore := false
	if newFolder {
		if wroteIgnore, err = report.IgnoreCases(reportsDir); err != nil {
			fmt.Fprintf(stderr, "shipward report new: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "opened %s (%s)\n\n", id, dir)
	printStages(stdout, c, id, now)
	fmt.Fprintf(stdout, "\nStart with %s. Fill in report.yaml as you learn more, then shipward report drafts %s --force.\n",
		filepath.Join(dir, report.DraftFile(report.EarlyWarning)), id)
	fmt.Fprintln(stdout, "These files describe something that may not be public yet: keep them out of public repositories.")
	if wroteIgnore {
		fmt.Fprintf(stdout, "Wrote %s, so git ignores the cases. In a private repository that should keep them, delete it.\n",
			filepath.Join(reportsDir, ".gitignore"))
	}
	if remote := report.TrackedWithRemote(dir); remote != "" {
		fmt.Fprintf(stderr, "warning: git does not ignore %s, and this repository has a remote (%s).\n"+
			"Commit report cases only to a private repository.\n", dir, remote)
	}
	return 0
}

func reportMark(kind string, args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("report "+kind, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	atFlag := fs.String("at", "", "when (default now)")
	skipped := fs.String("skipped", "", "done: the report was not sent, because its information was already provided (the reason)")
	dueFlag := fs.String("due", "", "intermediate: by when the CSIRT wants it")
	if err := parse(fs, args); err != nil {
		return 2
	}
	if kind == "intermediate" && *dueFlag == "" {
		fmt.Fprintln(stderr, "shipward report intermediate: --due is required (by when the CSIRT wants the report)")
		return 2
	}
	want := 1
	if kind == "done" {
		want = 2
	}
	if fs.NArg() != want {
		fmt.Fprint(stderr, reportUsage)
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report %s: %v\n", kind, err)
		return 1
	}
	id := fs.Arg(0)
	dir := filepath.Join(cfg.Resolve(cfg.Reports.Dir), id)
	c, err := report.Load(dir, time.Local)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report %s: %v\n", kind, err)
		return 1
	}
	at := now.Truncate(time.Second)
	if *atFlag != "" {
		if at, err = report.ParseTime(*atFlag, c.Location(time.Local)); err != nil {
			fmt.Fprintf(stderr, "shipward report %s: %v\n", kind, err)
			return 2
		}
		if at.After(now.Add(time.Minute)) {
			fmt.Fprintf(stderr, "shipward report %s: --at is in the future\n", kind)
			return 2
		}
	}
	if kind == "intermediate" {
		due, err := report.ParseTime(*dueFlag, c.Location(time.Local))
		if err != nil {
			fmt.Fprintf(stderr, "shipward report intermediate: %v\n", err)
			return 2
		}
		if due.Before(c.Aware) {
			fmt.Fprintln(stderr, "shipward report intermediate: --due is before you became aware")
			return 2
		}
		c.IntermediateDue = &due
	} else if kind == "fixed" {
		if c.Type == report.Incident {
			fmt.Fprintf(stderr, "shipward report fixed: %s is an incident; its final report is due one month after the notification, not after a fix\n", id)
			return 2
		}
		// A fix before awareness is allowed: an exploited flaw may be fixed in a newer release already.
		c.FixAvailable = &at
	} else {
		stage := fs.Arg(1)
		if report.DraftFile(stage) == "" {
			fmt.Fprintf(stderr, "shipward report done: unknown stage %q (%s)\n", stage, strings.Join(report.Stages, ", "))
			return 2
		}
		if stage == report.Intermediate && c.IntermediateDue == nil {
			fmt.Fprintf(stderr, "shipward report done: no intermediate report was asked for; record the CSIRT's request first "+
				"(shipward report intermediate %s --due TIME)\n", id)
			return 2
		}
		if *skipped != "" && !slices.Contains(report.Skippable, stage) {
			fmt.Fprintf(stderr, "shipward report done: --skipped is only for %s (Art. 14(2), (4): \"unless the relevant "+
				"information has already been provided\")\n", strings.Join(report.Skippable, " and "))
			return 2
		}
		if at.Before(c.Aware) {
			fmt.Fprintf(stderr, "shipward report done: --at %s is before you became aware (%s)\n",
				report.When(at, time.Local), report.When(c.Aware, time.Local))
			return 2
		}
		if prev := report.Previous(stage); prev != "" {
			sent, ok := c.Submitted[prev]
			switch {
			case !ok:
				fmt.Fprintf(stderr, "shipward report done: record the %s first (shipward report done %s %s --at TIME);\n"+
					"if you sent both together, record both with the same time\n", prev, id, prev)
				return 2
			case at.Before(sent):
				fmt.Fprintf(stderr, "shipward report done: --at %s is before the %s was sent (%s)\n",
					report.When(at, time.Local), prev, report.When(sent, time.Local))
				return 2
			}
		}
		if c.Submitted == nil {
			c.Submitted = map[string]time.Time{}
		}
		c.Submitted[stage] = at
		if *skipped != "" {
			if c.Skipped == nil {
				c.Skipped = map[string]string{}
			}
			c.Skipped[stage] = strings.TrimSpace(*skipped)
		} else {
			delete(c.Skipped, stage)
		}
	}
	if err := report.Save(dir, c); err != nil {
		fmt.Fprintf(stderr, "shipward report %s: %v\n", kind, err)
		return 1
	}
	if kind == "intermediate" {
		if _, err := report.WriteDrafts(dir, id, c, cfg, false, time.Local, "shipward "+version); err != nil {
			fmt.Fprintf(stderr, "shipward report intermediate: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "recorded the CSIRT's request; the draft is %s\n", filepath.Join(dir, report.DraftFile(report.Intermediate)))
	}
	switch next, open := c.Next(); {
	case open:
		fmt.Fprintf(stdout, "recorded. Next: %s, %s\n", next.Stage, stageStatus(next, c, id, now))
		fmt.Fprintf(stdout, "The drafts show the old dates until you run shipward report drafts %s --force (it overwrites edits).\n", id)
	case c.Closed():
		fmt.Fprintln(stdout, "recorded. Every stage of this case is done.")
	default:
		fmt.Fprintln(stdout, "recorded. Every report is sent.")
	}
	if users, _ := c.Deadline(report.Users); users.Done.IsZero() {
		fmt.Fprintf(stdout, "Also open, in parallel: users, %s (shipward report done %s users).\n", stageStatus(users, c, id, now), id)
	}
	return 0
}

func reportDrafts(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report drafts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml")
	force := fs.Bool("force", false, "overwrite drafts that exist")
	withCSAF := fs.Bool("csaf", false, "also write the users' notice as CSAF 2.0 (users.csaf.json)")
	if err := parse(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, reportUsage)
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report drafts: %v\n", err)
		return 1
	}
	id := fs.Arg(0)
	dir := filepath.Join(cfg.Resolve(cfg.Reports.Dir), id)
	c, err := report.Load(dir, time.Local)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report drafts: %v\n", err)
		return 1
	}
	written, err := report.WriteDrafts(dir, id, c, cfg, *force, time.Local, "shipward "+version)
	if err != nil {
		fmt.Fprintf(stderr, "shipward report drafts: %v\n", err)
		return 1
	}
	if *withCSAF {
		wrote, err := report.WriteNotice(dir, id, c, cfg, time.Now(), "shipward "+version, *force)
		if err != nil {
			fmt.Fprintf(stderr, "shipward report drafts: users' notice as CSAF: %v\n", err)
			return 2
		}
		if wrote {
			written = append(written, filepath.Join(dir, report.NoticeFile))
		}
	}
	if len(written) == 0 {
		fmt.Fprintln(stdout, "The drafts exist; --force writes them again from report.yaml.")
	}
	for _, w := range written {
		fmt.Fprintf(stdout, "wrote %s\n", w)
	}
	return 0
}
