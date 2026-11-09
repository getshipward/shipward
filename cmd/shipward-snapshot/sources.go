package main

import "github.com/getshipward/shipward/internal/snapshot"

// recordSources are the OSV record sources passed on, by ID prefix, with their terms (checked 6 Nov 2026,
// docs/data-sources.md). A record from any other source is dropped. Not passed on on purpose:
//   - MAL- (OpenSSF malicious packages): listing malicious software could make shipward "software that searches for
//     malicious software", an important product (CRA Annex III, class I).
//   - CGA- and other operating-system sources: licences ban commercial reuse or are share-alike or unknown.
var recordSources = []snapshot.RecordSource{
	{Prefix: "GHSA-", Source: snapshot.Source{Name: "GitHub Advisory Database", URL: "https://github.com/advisories", Licence: "CC-BY-4.0", Note: "filtered and shortened"}},
	{Prefix: "GO-", Source: snapshot.Source{Name: "Go Vulnerability Database", URL: "https://pkg.go.dev/vuln/", Licence: "CC-BY-4.0", Note: "filtered and shortened"}},
	{Prefix: "PYSEC-", Source: snapshot.Source{Name: "PyPA Advisory Database", URL: "https://github.com/pypa/advisory-database", Licence: "CC-BY-4.0", Note: "filtered and shortened"}},
	{Prefix: "RUSTSEC-", Source: snapshot.Source{Name: "RustSec Advisory Database", URL: "https://rustsec.org", Licence: "CC0-1.0 (parts from GitHub: CC-BY-4.0)", Note: "filtered and shortened"}},
	{Prefix: "DRUPAL-", Source: snapshot.Source{Name: "Drupal Security Advisories", URL: "https://www.drupal.org/security", Licence: "MIT", Note: "filtered and shortened"}},
	{Prefix: "OSV-", Source: snapshot.Source{Name: "OSS-Fuzz", URL: "https://github.com/google/oss-fuzz-vulns", Licence: "CC-BY-4.0", Note: "filtered and shortened"}},
}

// feedSources are the exploitation feeds the snapshot carries. ENISA's EUVD and FIRST's EPSS are not among them: shipward
// fetches those itself (internal/snapshot/live.go).
var feedSources = []snapshot.Source{
	{Name: "CISA Known Exploited Vulnerabilities Catalog", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", Licence: "CC0-1.0"},
}
