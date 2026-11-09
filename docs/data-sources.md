# Vulnerability data sources

`shipward scan` matches an SBOM against a signed snapshot of public vulnerability data, on the maker's own machine. The
snapshot is built once a day by `cmd/cra-snapshot` and published at `https://data.shipward.dev/v1/`.

The snapshot passes on only sources whose terms clearly allow passing on filtered data. Each one is named, with its
licence, in the snapshot index and in the output of `shipward scan` (attribution). Terms checked 6 Nov 2026 from the
licence files and terms pages.

| Source | In the snapshot | Terms |
|---|---|---|
| GitHub Advisory Database (`GHSA-`) | Yes | CC-BY-4.0; attribution by naming and linking it |
| Go vulndb (`GO-`), PyPA (`PYSEC-`), OSS-Fuzz (`OSV-`) | Yes | CC-BY-4.0 |
| RustSec (`RUSTSEC-`) | Yes | CC0-1.0, parts from GitHub CC-BY-4.0 |
| Drupal (`DRUPAL-`) | Yes | MIT |
| CISA Known Exploited Vulnerabilities | Yes | CC0-1.0; no CISA logo, no claim of endorsement |
| OpenSSF malicious packages (`MAL-`) | **No** | Apache-2.0, but out of scope: Shipward does not search for malicious software |
| Chainguard/Wolfi (`CGA-`), MinimOS | **No** | CC BY-NC-ND 4.0 |
| Ubuntu, Alpine | No (not language ecosystems) | Share-alike |
| ENISA EUVD (exploited list) | **No**: `shipward` fetches it from ENISA itself, cached 20 h | No data licence; terms unclear |
| FIRST EPSS | **No**: `shipward` fetches the CSV itself, cached 20 h | No licence; attribution requested; terms unclear |

Any other record source is dropped (`cmd/cra-snapshot/sources.go`).

Why a snapshot instead of OSV's own files: passing on the CC-BY data with attribution is allowed, and it keeps
downloads small (npm: 0.7 MB instead of 210 MB) and signed. Old RubyGems records may carry OSVDB text
(ruby-advisory-db LICENSE); GitHub republishes them under CC-BY-4.0.
