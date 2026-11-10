package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getshipward/shipward/internal/advisory"
	"github.com/getshipward/shipward/internal/config"
)

// NoticeFile is the machine-readable form of the users' notice in a case folder.
const NoticeFile = "users.csaf.json"

// NoticeDescription is the description a CSAF notice starts with. The case's summary, severity and impact are written
// for the CSIRT and may say how the flaw works, so they are not copied into a notice for users.
const NoticeDescription = "TODO: in plain words, what this means for users. Before a fix exists, leave out how the flaw works."

// Notice builds the users' notice of a case as a CSAF 2.0 security advisory (CRA Art. 14(8): "where appropriate in a
// structured, machine-readable format"), for the time before a fix: the affected versions, the IDs, and what users
// can do (user_measures) as a mitigation. It takes nothing from the fields written for the CSIRT (summary, severity,
// impact). After the fix, the advisory comes from shipward advisory. The document is a draft to check.
func Notice(id string, c *Case, cfg *config.Config, now time.Time, tool string) ([]byte, error) {
	if len(c.Versions) == 0 {
		return nil, errors.New("CSAF needs the affected versions (versions in report.yaml)")
	}
	a := advisory.Advisory{ID: id, Title: "Security notice: " + c.Title, Product: cfg.Product.Name,
		Manufacturer: cfg.Manufacturer.Name, Namespace: cfg.Manufacturer.URL, Affected: c.Versions,
		Description: NoticeDescription, Date: now, Tool: tool, Unfixed: true,
		Remediation: strings.Join(c.UserMeasures, "\n")}
	// The vulnerability's own IDs name it better than the case folder.
	for _, x := range c.Advisories {
		if a.ID == id {
			a.ID = x
		} else {
			a.Aliases = append(a.Aliases, x)
		}
	}
	return advisory.CSAF(a)
}

// WriteNotice writes users.csaf.json into the case folder, privately. An existing file is kept unless force is set.
// It reports whether it wrote the file.
func WriteNotice(dir, id string, c *Case, cfg *config.Config, now time.Time, tool string, force bool) (bool, error) {
	path := filepath.Join(dir, NoticeFile)
	if _, err := os.Stat(path); err == nil && !force {
		return false, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	body, err := Notice(id, c, cfg, now, tool)
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(path, body, 0o600)
}
