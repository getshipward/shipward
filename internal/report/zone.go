package report

import (
	"os"
	"strings"
	"time"
	_ "time/tzdata" // zone names work on computers without a zone database (Windows, small CI images)
)

// LocalZone returns the IANA name of this computer's time zone (Europe/Ljubljana), or "" when it cannot be found. A
// case keeps it in report.yaml, so every computer counts its months and reads its times without an offset the same way.
func LocalZone() string {
	var names []string
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" {
		names = append(names, tz)
	} else {
		if link, err := os.Readlink("/etc/localtime"); err == nil {
			if i := strings.Index(link, "zoneinfo/"); i >= 0 {
				names = append(names, link[i+len("zoneinfo/"):])
			}
		}
		if b, err := os.ReadFile("/etc/timezone"); err == nil {
			names = append(names, strings.TrimSpace(string(b)))
		}
	}
	return pickZone(names, time.Local)
}

// pickZone returns the first name that is a time zone with the same offset as local now, or "".
func pickZone(names []string, local *time.Location) string {
	now := time.Now()
	_, want := now.In(local).Zone()
	for _, name := range names {
		if name == "" || name == "Local" || strings.HasPrefix(name, "/") {
			continue
		}
		loc, err := time.LoadLocation(name)
		if err != nil {
			continue
		}
		if _, off := now.In(loc).Zone(); off == want {
			return name
		}
	}
	return ""
}

// Location returns the case's time zone: Zone, or fallback when Zone is empty. Validate checks Zone.
func (c Case) Location(fallback *time.Location) *time.Location {
	if c.Zone != "" {
		if loc, err := time.LoadLocation(c.Zone); err == nil {
			return loc
		}
	}
	return fallback
}

// in gives t in the case's zone or, without one, in a fixed zone with t's own offset. The result never depends on the
// time zone of the computer that runs shipward (time.Parse uses it when the offset happens to match).
func (c Case) in(t time.Time) time.Time {
	if c.Zone != "" {
		if loc, err := time.LoadLocation(c.Zone); err == nil {
			return t.In(loc)
		}
	}
	name, off := t.Zone()
	if off == 0 && name == "UTC" {
		return t.UTC()
	}
	return t.In(time.FixedZone("", off))
}

// normalise puts every time of the case in its zone (see in).
func (c *Case) normalise() {
	c.Aware = c.in(c.Aware)
	if c.FixAvailable != nil {
		t := c.in(*c.FixAvailable)
		c.FixAvailable = &t
	}
	if c.IntermediateDue != nil {
		t := c.in(*c.IntermediateDue)
		c.IntermediateDue = &t
	}
	for k, t := range c.Submitted {
		c.Submitted[k] = c.in(t)
	}
}
