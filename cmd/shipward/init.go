package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/docs"
)

// starterConfig is written when there is no shipward.yaml yet. The commented keys feed shipward init's drafts.
const starterConfig = `# Settings for Shipward: https://shipward.dev/docs/getting-started/
product:
  name: %s
  # description: one sentence on what the product is
  # purpose: who uses it, for what, and where
  # website: https://example.com
  # support_until: "2031-12"     # end of the support period (YYYY-MM)
  # licence: LicenseRef-example-proprietary
manufacturer:
  name: %s
%s  # address: "Street 1, 1000 City, Country"
# security:
#   contact: mailto:security@example.com   # default: the manufacturer's email
#   policy: https://example.com/security   # where SECURITY.md is published
#   languages: [en]
`

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to shipward.yaml (written when it does not exist)")
	product := fs.String("product", "", "product name (for a new shipward.yaml)")
	manufacturer := fs.String("manufacturer", "", "manufacturer name (for a new shipward.yaml)")
	email := fs.String("email", "", "manufacturer e-mail (for a new shipward.yaml)")
	url := fs.String("url", "", "manufacturer website (for a new shipward.yaml)")
	only := fs.String("only", "", "comma-separated documents to write: "+docNames())
	force := fs.Bool("force", false, "overwrite documents that exist")
	if err := parse(fs, args); err != nil {
		return 2
	}

	if _, err := os.Stat(*cfgPath); errors.Is(err, os.ErrNotExist) {
		if err := config.OldName(*cfgPath); err != nil {
			fmt.Fprintf(stderr, "shipward init: %v\n", err)
			return 2
		}
		if *product == "" || *manufacturer == "" {
			fmt.Fprintf(stderr, "shipward init: no %s yet: give --product and --manufacturer (and --email, --url)\n", *cfgPath)
			return 2
		}
		extra := ""
		if *email != "" {
			extra += "  email: " + quote(*email) + "\n"
		}
		if *url != "" {
			extra += "  url: " + quote(*url) + "\n"
		}
		body := fmt.Sprintf(starterConfig, quote(*product), quote(*manufacturer), extra)
		if err := writeFile(*cfgPath, func(w io.Writer) error { _, err := io.WriteString(w, body); return err }); err != nil {
			fmt.Fprintf(stderr, "shipward init: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s: fill in the commented settings, then run shipward init again for fuller drafts\n", *cfgPath)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "shipward init: %v\n", err)
		return 1
	}
	var names []string
	if *only != "" {
		names = strings.Split(*only, ",")
	}
	results, err := docs.Write(cfg, names, *force, time.Now(), "shipward "+version)
	if err != nil {
		fmt.Fprintf(stderr, "shipward init: %v\n", err)
		return 1
	}
	total := 0
	for _, r := range results {
		state := "kept (exists; --force overwrites)"
		if r.Written {
			state = "wrote"
		}
		fmt.Fprintf(stdout, "%-36s %-36s %d TODO\n", r.Path, state, r.TODOs)
		total += r.TODOs
	}
	fmt.Fprintf(stdout, "\n%d TODOs to fill in. These are drafts that follow the CRA's lists; they are not legal advice.\n", total)
	fmt.Fprintln(stdout, "Publish security.txt at https://<your website>/.well-known/security.txt. Sign the declaration of conformity only when the technical documentation is complete.")
	return 0
}

// quote makes a YAML scalar of s.
func quote(s string) string {
	b, err := yaml.Marshal(s)
	if err != nil {
		return `""`
	}
	return strings.TrimSpace(string(b))
}

func docNames() string {
	var n []string
	for _, d := range docs.All {
		n = append(n, d.Name)
	}
	return strings.Join(n, ", ")
}
