package osv

import "testing"

func TestAffects(t *testing.T) {
	nuget := Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json"}
	v := Vulnerability{ID: "GHSA-1", Affected: []Affected{{
		Package: nuget,
		Ranges:  []Range{{Type: "ECOSYSTEM", Events: []Event{{Fixed: "13.0.1"}, {Introduced: "0"}}}},
	}, {
		Package:  Package{Ecosystem: "NuGet", Name: "Other"},
		Ranges:   []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "2.0.0"}, {LastAffected: "2.1.0"}}}},
		Versions: []string{"1.0.0-beta"},
	}}}
	tests := []struct {
		p       Package
		version string
		want    bool
	}{
		{nuget, "12.0.1", true},
		{nuget, "13.0.1", false},
		{nuget, "13.0.3", false},
		{Package{Ecosystem: "NuGet", Name: "newtonsoft.json"}, "12.0.1", true}, // NuGet ignores case
		{Package{Ecosystem: "npm", Name: "Newtonsoft.Json"}, "12.0.1", false},
		{Package{Ecosystem: "NuGet", Name: "Other"}, "1.9.9", false},
		{Package{Ecosystem: "NuGet", Name: "Other"}, "2.1.0", true},
		{Package{Ecosystem: "NuGet", Name: "Other"}, "2.1.1", false},
		{Package{Ecosystem: "NuGet", Name: "Other"}, "1.0.0-beta", true},
	}
	for _, tt := range tests {
		if got := v.Affects(tt.p, tt.version); got != tt.want {
			t.Errorf("Affects(%s %s) = %v, want %v", tt.p.Name, tt.version, got, tt.want)
		}
	}
	v.Withdrawn = "2026-01-01T00:00:00Z"
	if v.Affects(nuget, "12.0.1") {
		t.Error("withdrawn record still matches")
	}
}

func TestFromPURL(t *testing.T) {
	tests := []struct {
		purl, eco, name, version string
	}{
		{"pkg:nuget/MessagePack@3.1.12", "NuGet", "MessagePack", "3.1.12"},
		{"pkg:npm/%40vue/reactivity@3.5.0", "npm", "@vue/reactivity", "3.5.0"},
		{"pkg:composer/laravel/framework@v13.1.0", "Packagist", "laravel/framework", "v13.1.0"},
		{"pkg:golang/golang.org/x/net@v0.62.0", "Go", "golang.org/x/net", "0.62.0"},
		{"pkg:golang/stdlib@go1.26.10", "Go", "stdlib", "1.26.10"},
		{"pkg:pypi/Django_Rest@1.0", "PyPI", "django-rest", "1.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"},
	}
	for _, tt := range tests {
		p, v, ok := FromPURL(tt.purl)
		if !ok || p.Ecosystem != tt.eco || p.Name != tt.name || v != tt.version {
			t.Errorf("FromPURL(%s) = %+v %q %v", tt.purl, p, v, ok)
		}
	}
	for _, bad := range []string{"", "pkg:github/godotengine/godot@4.7.2-stable", "pkg:nuget/NoVersion"} {
		if _, _, ok := FromPURL(bad); ok {
			t.Errorf("FromPURL(%q) ok", bad)
		}
	}
}

func TestParse(t *testing.T) {
	data := `{"id":"GHSA-5crp-9r3c-p9vr","aliases":["CVE-2024-21907"],"details":"long text",
	  "affected":[{"package":{"ecosystem":"NuGet","name":"Newtonsoft.Json"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"13.0.1"}]}]},
	              {"package":{"ecosystem":"npm","name":"x"}}],
	  "references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-21907"},{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr"}],
	  "database_specific":{"severity":"HIGH"}}`
	v, err := Parse([]byte(data), "NuGet")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Affected) != 1 || v.URL != "https://github.com/advisories/GHSA-5crp-9r3c-p9vr" || v.Rating != "HIGH" {
		t.Errorf("Parse = %+v", v)
	}
	if got := v.CVEs(); len(got) != 1 || got[0] != "CVE-2024-21907" {
		t.Errorf("CVEs = %q", got)
	}
	if got := v.Fixed(Package{Ecosystem: "NuGet", Name: "newtonsoft.json"}); len(got) != 1 || got[0] != "13.0.1" {
		t.Errorf("Fixed = %q", got)
	}
}
