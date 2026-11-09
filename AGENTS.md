# Shipward

A command-line tool (`shipward`) and a GitHub Action that help small software makers prepare for the EU Cyber Resilience
Act (CRA). See `README.md`.

## Rules

- **No user data on our servers.** `shipward` runs in the maker's own build and on their own computer. Our only server
  part publishes a signed daily snapshot of public vulnerability data, and it receives no package names, SBOMs,
  findings or documents.
- **Wording.** Call it a security tool. Never "document management", "archive" or "storage of records". Never
  promise to keep files for years, and add no features to index, manage or retrieve documents.
- **CRA default class.** Never block, remove or quarantine anything, and no log correlation. Never search for
  malicious software: no malicious-package records (OSV `MAL-`) in the snapshot, and never "malware" in our wording.
- **Claims.** Never "CRA compliant", "certified" or "approved". Say "helps you prepare". Every generated file carries
  a disclaimer.
- **Data sources.** Only pass on data whose terms allow it: [`docs/data-sources.md`](docs/data-sources.md).

## Stack

- Go, one module at the repo root. The binary is `cmd/shipward`; the snapshot builder is `cmd/cra-snapshot`.
- Tests: `go test ./...`. No database.

## Changes

- Every change goes in as a pull request to `main`. The required check is `test` (`.github/workflows/ci.yml`).
  Squash merges only.
- Pin GitHub Actions to commit SHAs.
- Never commit secrets, tokens or user data.
