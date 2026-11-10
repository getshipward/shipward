<p align="center">
  <a href="https://shipward.dev"><img src=".github/logo.svg" alt="Shipward" width="88" height="88"></a>
</p>

<h1 align="center">Shipward</h1>

<p align="center">
  <strong>Get your software ready for the EU Cyber Resilience Act, in your own repository.</strong>
</p>

<p align="center">
  <a href="https://shipward.dev">Website</a> ·
  <a href="https://shipward.dev/docs/">Docs</a> ·
  <a href="https://shipward.dev/docs/getting-started/">Getting started</a> ·
  <a href="https://shipward.dev/docs/github-action/">GitHub Action</a>
</p>

<p align="center">
  <a href="https://github.com/getshipward/shipward/actions/workflows/ci.yml"><img src="https://github.com/getshipward/shipward/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-4f46e5" alt="Licence: Apache-2.0"></a>
</p>

Shipward is a command-line tool and a GitHub Action for small software makers. It lists every component of your
product, finds known vulnerabilities in its packages from eight ecosystems (npm, NuGet, Composer, Go, PyPI, Maven,
Rust, RubyGems), and keeps your decisions about each one. Everything it makes stays in your repository.

> [!NOTE]
> Shipward is early: we use it for our own products, and commands and files can still change. It helps you prepare
> for the CRA. It lists facts about your software; it does not certify anything and is not legal advice.

## What it does

| Command | What you get | Docs |
|---|---|---|
| `shipward sbom` | A CycloneDX 1.6 SBOM from your lock files, plus the parts no package manager knows (a game engine, vendored code) | [SBOM](https://shipward.dev/docs/sbom/) |
| `shipward check sbom` | The SBOM fields Germany's BSI TR-03183-2 asks for that your SBOM misses | [SBOM fields](https://shipward.dev/docs/sbom-fields/) |
| `shipward licences` | Licences a person checked, kept in `licences.yaml` and written into the SBOM | [Licences](https://shipward.dev/docs/licences/) |
| `shipward scan` | Known vulnerabilities in npm, NuGet, Composer, Go, PyPI, Maven, Rust and RubyGems packages, matched on your machine against a daily, signed snapshot of public advisories; it counts the components it cannot check | [Vulnerability scan](https://shipward.dev/docs/scan/) |
| `shipward triage` | Your decision on each advisory (VEX), in `vex.yaml`, exported as OpenVEX | [Decisions (VEX)](https://shipward.dev/docs/decisions/) |
| `shipward init` | Drafts of your security policy, `security.txt`, user information, declaration of conformity and technical documentation | [CRA documents](https://shipward.dev/docs/documents/) |
| `shipward advisory` | A draft advisory about a fixed vulnerability (CRA Annex I Part II(4)), in Markdown and CSAF 2.0 | [Advisories](https://shipward.dev/docs/advisories/) |
| `shipward report` | Drafts of the 24-hour, 72-hour and final reports (CRA Article 14), with their deadlines | [Reports](https://shipward.dev/docs/reports/) |
| `uses: getshipward/shipward` | `sbom`, `check sbom`, `scan` and `triage export` on every push, with the results in the job summary (not `init`, `licences` or `report`) | [GitHub Action](https://shipward.dev/docs/github-action/) |

## Quick start

Put a `shipward.yaml` in the root of your product's repository:

```yaml
product:
  name: Example Game
  licence: MIT                  # the SPDX expression you distribute the product under
manufacturer:
  name: Example Studio
  url: https://example.com
  email: security@example.com
```

Then:

```sh
shipward sbom --version 1.4.0   # writes sbom/sbom.cdx.json
shipward check sbom             # which SBOM fields are missing
shipward scan                   # known vulnerabilities in your components
shipward triage                 # the advisories that still need your decision
```

Or run it in CI:

```yaml
jobs:
  shipward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit>
      - uses: getshipward/shipward@<commit>   # pin a commit
        with:
          fail-on: none                       # or open, exploited, unchecked
```

To hear about a missed report deadline, run `shipward report --fail-on overdue` on a schedule, in a private repository
that holds your report cases ([Report deadlines](https://shipward.dev/docs/github-action/#report-deadlines)).

The full guide: [shipward.dev/docs](https://shipward.dev/docs/).

## How it works

- **Your data stays yours.** `shipward` runs on your computer and in your CI. No account, no upload: no package names,
  SBOMs, findings or decisions leave your machine. `shipward scan --offline` sends nothing at all.
- **Signed public data.** The only thing that comes from us is a daily snapshot of public advisories at
  `data.shipward.dev`, from sources whose terms allow it, signed with Ed25519 and checked file by file
  ([Data sources](https://shipward.dev/docs/data/); the terms per source: [`docs/data-sources.md`](docs/data-sources.md)).
- **It reports, you decide.** Shipward never blocks, removes or changes your software. Whether a finding stops a
  release is your setting (`--fail-on`); by default it never does.

## Build from source

```sh
git clone https://github.com/getshipward/shipward.git
cd shipward
go build -o shipward ./cmd/shipward
./shipward version
```

Tests: `go test ./...`. Shipward bundles [Syft](https://github.com/anchore/syft) (Apache-2.0) as a library; `NOTICE`
lists the bundled libraries and data sources. CI accepts only the Go vulnerabilities listed, each with its reason, in
`.govulncheck-allow`.

Releases are built by `.github/workflows/release.yml` from a tag `vX.Y.Z`: binaries for Linux, macOS and Windows,
Shipward's own SBOM, and `SHA256SUMS` signed with cosign (keyless, Sigstore). The workflow file says how to verify
them. Shipward's own decisions about advisories in its dependencies are in [`vex.yaml`](vex.yaml).

## Security

Please report a vulnerability in Shipward privately, through
[GitHub's private reporting](https://github.com/getshipward/shipward/security/advisories/new) or by e-mail
(see [Security and privacy](https://shipward.dev/docs/security/)).

## Licence

Apache-2.0: see [`LICENSE`](LICENSE).
