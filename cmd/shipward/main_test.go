package main

import (
	"bytes"
	"context"
	"flag"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"version"}, 0, "dev\n"},
		{nil, 2, ""},
		{[]string{"nope"}, 2, ""},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), tt.args, &stdout, &stderr); code != tt.code {
			t.Errorf("run(%q) = %d, want %d", tt.args, code, tt.code)
		}
		if got := stdout.String(); got != tt.out {
			t.Errorf("run(%q) stdout = %q, want %q", tt.args, got, tt.out)
		}
	}
}

func TestParseFlagsAfterArguments(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	format := fs.String("format", "text", "")
	all := fs.Bool("all", false, "")
	out := fs.String("o", "", "")
	if err := parse(fs, []string{"sbom.json", "--format", "json", "--all", "-o", "-", "extra"}); err != nil {
		t.Fatal(err)
	}
	if *format != "json" || !*all || *out != "-" || len(fs.Args()) != 2 || fs.Arg(0) != "sbom.json" || fs.Arg(1) != "extra" {
		t.Errorf("format %q all %v o %q args %q", *format, *all, *out, fs.Args())
	}
}
