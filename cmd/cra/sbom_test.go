package main

import (
	"testing"

	"github.com/getshipward/shipward/internal/config"
)

func TestSetForm(t *testing.T) {
	var p config.Product
	if err := setForm(&p, "executable, bundle"); err != nil {
		t.Fatal(err)
	}
	if !*p.Executable || !*p.Archive || *p.Structured {
		t.Errorf("form = %v %v %v", *p.Executable, *p.Archive, *p.Structured)
	}
	if err := setForm(&p, "none"); err != nil || *p.Executable || *p.Archive || *p.Structured {
		t.Errorf("none: %v", err)
	}
	if err := setForm(&p, "zip"); err == nil {
		t.Error("zip accepted")
	}
}
