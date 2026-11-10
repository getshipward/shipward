package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without an e-mail or a security contact, init still writes security.txt, but with a TODO in Contact (RFC 9116
// requires the field), counts it, and warns.
func TestInitWarnsWithoutContact(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	if code := runInit([]string{"--product", "App", "--manufacturer", "Maker", "--only", "security.txt"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning: no security contact") {
		t.Errorf("stderr = %q, want a warning about the missing contact", stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "cra", "security.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nContact: TODO: ") {
		t.Errorf("security.txt:\n%s", b)
	}
	if strings.Contains(stdout.String(), " 0 TODO") {
		t.Errorf("the TODO in Contact is not counted:\n%s", stdout.String())
	}

	// With an e-mail there is no warning.
	stderr.Reset()
	os.WriteFile(filepath.Join(dir, "shipward.yaml"), []byte("product:\n  name: App\nmanufacturer:\n  name: Maker\n  email: s@example.com\n"), 0o644)
	if code := runInit([]string{"--only", "security.txt", "--force"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}
