# Shipward

A command-line tool and GitHub Action that help a small software maker prepare for the EU Cyber Resilience Act: SBOMs,
local vulnerability checks, VEX decisions, report drafts with deadlines, and templates. Everything stays in the
maker's own repository.

- Vulnerability data and its terms: [`docs/data-sources.md`](docs/data-sources.md)

## Use

Put a `cra.yaml` in the product's repository:

```yaml
product:
  name: Example Game
  licence: MIT                    # SPDX expression the product is distributed under
  executable: true                # the delivered file (BSI TR-03183-2); leave out what you do not know
  archive: false
  structured: false
manufacturer:
  name: Example Studio
  url: https://example.com
  email: security@example.com
sbom:
  path: .                         # what to scan (default .)
  exclude: ["./tests/**"]         # Syft globs; ./.github/** is always left out
  output: sbom/sbom.cdx.json      # default
```

List what no package manager knows about (the engine, copied add-ons, vendored code) in `components.extra.yaml`:

```yaml
components:
  - name: godot
    version: 4.7.2-stable
    type: framework
    purl: pkg:github/godotengine/godot@4.7.2-stable
    supplier: Godot Foundation
    url: https://godotengine.org
    licenses: [MIT]
    creator: https://godotengine.org                              # email or URL of who made it
    source: https://github.com/godotengine/godot/tree/4.7.2-stable
    executable: true
    archive: false
    structured: false
    # download: <URL of the file you used>, filename: <its name>, hashes: {sha512: <its SHA-512>}
```

Drafts of the CRA documents, from what `cra.yaml` knows (the rest is marked TODO):

```sh
cra init --product "Example Game" --manufacturer "Example Studio" --email security@example.com   # no cra.yaml yet: writes one too
cra init                      # SECURITY.md, cra/security.txt, cra/user-information.md (Annex II),
                              # cra/declaration-of-conformity.md (Annex V, unsigned), cra/technical-documentation.md (Annex VII)
cra init --only security.txt --force   # renew one draft
```

It never overwrites a file without `--force`, and prints the number of TODOs per file. The settings it uses:
`product.description`, `purpose`, `website`, `support_until` (YYYY-MM), `manufacturer.address`,
`security.contact` (default `mailto:` and the manufacturer's email), `security.policy`, `security.languages`,
`docs.dir` (default `cra`).

Then, per release:

```sh
cra sbom --version 1.2.3      # writes sbom/sbom.cdx.json (CycloneDX 1.6)
cra sbom --version 1.2.3 --artifact build/game.exe --artifact-url https://example.com/game.exe
                              # adds the delivered file's name and SHA-512
cra sbom -o -                 # or print it
cra check sbom                # list fields missing for BSI TR-03183-2 v2.1.0 (exit 1 if a required one is missing)
cra check sbom --all file.json
```

`cra sbom` fills only what local files state as facts. It looks nothing up online.

- Every component gets a dependencies entry, plus a completeness statement "unknown" (a scan cannot prove it found
  everything).
- Licences from package metadata are "declared". A "concluded" licence (BSI: distribution licence) comes only from
  `licences.yaml`, which a person checks.
- Registry packages (npm, NuGet, Composer, Go, ...) are package files: non-executable, archive, structured
  (TR-03183-2 table 7).
- npm, yarn, pnpm: SHA-512, download URL and filename from the lock file.
- NuGet: SHA-512 of the `.nupkg` file, download URL (nuget.org only), creator URL, source URL and declared licence,
  read from the NuGet global packages folder (`$NUGET_PACKAGES` or `~/.nuget/packages`; `--nuget-packages` changes
  it). Run `dotnet restore` first. The lock file's `contentHash` is not used: for signed packages it is not the hash
  of the file.
- .NET project references (your own projects) take the product's creator, version and licence.

Still open: the creator of npm, Composer and Go packages, and the hash of Composer and Go packages. These need an
online lookup, which will be opt-in.

### Reports (CRA Article 14)

When you learn of an actively exploited vulnerability or a severe incident in your product:

```sh
cra report new vulnerability --title "Exploited flaw in login" --aware "2026-11-06 14:00" --advisory CVE-2026-1234
cra report                         # every open case: the next report, its deadline, the time left
cra report done CASE early-warning # after you submitted it on ENISA's single reporting platform
cra report fixed CASE              # a fix or mitigation is available: the final report is due 14 days later
cra report drafts CASE --force     # write the drafts again after you changed report.yaml
cra report --fail-on overdue       # exit 3 when a report is overdue (for a scheduled CI job)
```

Each case is a folder in `cra/reports/` (`reports.dir`): `report.yaml` with the facts and times, and drafts of the
early warning (24 h), the notification (72 h), the final report (vulnerability: 14 days after the fix; incident: one
month after the notification) and the notice to users, with the contents Article 14 asks for. A person submits them
on the platform, which has no API. Settings: `reports.csirt` (your CSIRT coordinator, e.g. SI-CERT),
`product.markets` (the Member States where the product is available, or `[EU]`).

**The cases describe what may not be public yet: keep them out of public repositories.** The files are written for
the owner only.

### Licences

```sh
cra licences                  # list components without a confirmed licence
cra licences --write          # add an entry per component with one declared licence to licences.yaml
```

Check every entry `--write` adds before you commit `licences.yaml`: by committing it, you confirm the licences. An
entry without `@version` applies to every version while the declared licence stays the same:

```yaml
- component: pkg:nuget/MessagePack
  declared: MIT
  concluded: MIT
```

Run `cra sbom` again afterwards.

Scan a clean checkout (as CI does), not a folder with old build output: local build folders add packages the product
no longer ships.

**.NET:** Syft reads `packages.lock.json`, not `.csproj`. Turn on lock files once
(`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in `Directory.Build.props`), run `dotnet restore`
and commit the lock files. Without them the SBOM has no NuGet packages.

### Scan

```sh
cra scan                      # match sbom/sbom.cdx.json against the daily vulnerability snapshot
cra scan --format json file.json
cra scan --offline            # no requests: the cached snapshot and feeds only
```

`cra scan` downloads a signed snapshot of public vulnerability data from `https://data.shipward.dev/v1/` (only the
ecosystems in the SBOM, cached in `~/.cache/shipward`), checks its Ed25519 signature and SHA-256s, and matches on this
machine. It sends no package names anywhere. It also fetches ENISA's exploited list and FIRST's EPSS scores from
those sources (cached 20 hours): their terms do not clearly let us pass them on. An advisory that names a version
does not prove the product is affected; `cra triage` (next) records that decision.

### Decisions (VEX)

An advisory that names a component version may not affect the product: the vulnerable code may never run. Record
that decision, so the next scan shows it and others can read it:

```sh
cra triage                    # advisories without a final decision, with a ready cra triage set line each
cra triage set GHSA-5crp-9r3c-p9vr pkg:nuget/Newtonsoft.Json@12.0.1 --status not_affected \
  --justification vulnerable_code_not_in_execute_path --impact "We never parse untrusted JSON." --by alex
cra triage set CVE-2021-26701 pkg:nuget/System.Text.Encodings.Web@4.5.0 --status affected \
  --action "Update to 1.0.1." --by alex
cra triage export             # writes sbom/vex.openvex.json (OpenVEX 0.2.0) for users and scanners
```

Decisions live in `vex.yaml` (commit it; comments are kept). Statuses and justifications are OpenVEX's:
`not_affected` (needs `--justification` or `--impact`), `affected` (needs `--action`), `fixed`,
`under_investigation`. A decision can name the advisory by any of its IDs (GHSA or CVE); `--all-versions` applies it
to every version of the component. `cra triage` also lists decisions that no advisory needs any more.

### In CI

```sh
cra scan --summary "$GITHUB_STEP_SUMMARY"      # a Markdown table in the job summary
cra scan --format json > scan.json
cra scan --fail-on exploited                   # exit 3 when an undecided advisory is known to be exploited
cra scan --fail-on open                        # exit 3 when any advisory has no final decision
```

`--fail-on` is off by default: `cra` reports, the maker decides what stops a release.

### GitHub Action

```yaml
jobs:
  cra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: dotnet restore --locked-mode        # .NET: hashes and creators come from the restored packages
      - uses: getshipward/shipward@<commit>      # pin a commit or a release tag
        with:
          fail-on: none                          # or open, exploited
```

It builds `cra` from this repository at the pinned ref, then runs `cra sbom`,
`cra check sbom`, `cra scan` and `cra triage export`. Results: the job summary, the outputs `open` and `exploited`,
and a workflow artifact (`sbom/` by default). Inputs: `action.yml`.

### Releases

Push a tag `vX.Y.Z`. `.github/workflows/release.yml` builds `cra` for Linux, macOS and Windows (amd64, arm64), makes
cra's own SBOM, writes `SHA256SUMS` and signs it with cosign (keyless, Sigstore). The workflow file says how to
verify. cra's own decisions about advisories in its dependencies are in `vex.yaml`.

The snapshot is built once a day by `cra-snapshot` (image `ghcr.io/getshipward/cra-snapshot`). Sources and terms:
[`docs/data-sources.md`](docs/data-sources.md).

## Develop

```sh
go test ./...
go run ./cmd/cra version
```

`cra` bundles [Syft](https://github.com/anchore/syft) (Apache-2.0) as a library: see `NOTICE`. CI accepts the
vulnerabilities listed in `.govulncheck-allow`, each with its reason (package-level scan: the full call-graph scan needs
5–7 GB).
