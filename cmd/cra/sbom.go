package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/getshipward/shipward/internal/config"
	"github.com/getshipward/shipward/internal/sbom"
)

func runSBOM(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultFile, "path to cra.yaml")
	ver := fs.String("version", "", "product version for this release (overrides product.version)")
	out := fs.String("o", "", `output file, or "-" for stdout (overrides sbom.output)`)
	artifact := fs.String("artifact", "", "the delivered file of this release; its name and SHA-512 go into the SBOM")
	artifactURL := fs.String("artifact-url", "", "where the delivered file can be downloaded")
	form := fs.String("form", "", `what the delivered file is, for the BSI fields: a list of executable, bundle (it holds other files) and structured ("executable,bundle"), or none. Overrides the product's settings in cra.yaml`)
	nugetCache := fs.String("nuget-packages", sbom.DefaultNuGetCache(), "NuGet global packages folder, read for hashes and creators (empty: skip)")
	if err := parse(fs, args); err != nil {
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "cra sbom: %v\n", err)
		return 1
	}
	extra, err := sbom.LoadExtra(cfg.Resolve(cfg.SBOM.Extra))
	if err != nil {
		fmt.Fprintf(stderr, "cra sbom: %v\n", err)
		return 1
	}
	licences, err := sbom.LoadLicences(cfg.Resolve(cfg.SBOM.Licences))
	if err != nil {
		fmt.Fprintf(stderr, "cra sbom: %v\n", err)
		return 1
	}
	if *form != "" {
		if err := setForm(&cfg.Product, *form); err != nil {
			fmt.Fprintf(stderr, "cra sbom: %v\n", err)
			return 2
		}
	}
	productVersion := cfg.Product.Version
	if *ver != "" {
		productVersion = *ver
	}

	bom, err := sbom.Generate(ctx, sbom.Options{
		Path:    cfg.Resolve(cfg.SBOM.Path),
		Exclude: cfg.SBOM.Exclude,
		Product: cfg.Product.Name,
		Version: productVersion,
		Manufacturer: sbom.Supplier{
			Name:  cfg.Manufacturer.Name,
			URL:   cfg.Manufacturer.URL,
			Email: cfg.Manufacturer.Email,
		},
		Extra:          extra,
		Licences:       licences,
		ToolVersion:    version,
		ProductLicence: cfg.Product.Licence,
		ProductForm: sbom.Form{
			Executable: cfg.Product.Executable,
			Archive:    cfg.Product.Archive,
			Structured: cfg.Product.Structured,
		},
		Artifact:    *artifact,
		ArtifactURL: *artifactURL,
		NuGetCache:  *nugetCache,
	})
	if err != nil {
		fmt.Fprintf(stderr, "cra sbom: %v\n", err)
		return 1
	}

	target := cfg.Resolve(cfg.SBOM.Output)
	if *out != "" {
		target = *out
	}
	if target == "-" {
		if err := sbom.Write(stdout, bom); err != nil {
			fmt.Fprintf(stderr, "cra sbom: %v\n", err)
			return 1
		}
		return 0
	}
	if err := writeFile(target, func(w io.Writer) error { return sbom.Write(w, bom) }); err != nil {
		fmt.Fprintf(stderr, "cra sbom: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (%d components, %d from %s)\n", target, sbom.Count(bom), len(extra), cfg.SBOM.Extra)
	return 0
}

// setForm sets the product's BSI form properties from a --form list: the named ones true, the others false. "bundle"
// is BSI's archive property: a file that holds other files.
func setForm(p *config.Product, list string) error {
	set := map[string]bool{}
	if list != "none" {
		for _, f := range strings.Split(list, ",") {
			switch f = strings.TrimSpace(f); f {
			case "executable", "bundle", "structured":
				set[f] = true
			default:
				return fmt.Errorf("--form: %q is not executable, bundle, structured or none", f)
			}
		}
	}
	e, a, s := set["executable"], set["bundle"], set["structured"]
	p.Executable, p.Archive, p.Structured = &e, &a, &s
	return nil
}

// writeFile writes through a temporary file, so a failed run never leaves half an SBOM behind.
func writeFile(path string, write func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cra-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := write(tmp); err != nil {
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
