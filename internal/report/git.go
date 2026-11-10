package report

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ignoreFile keeps report cases out of git by default: they describe vulnerabilities and incidents that may not be
// fixed or public yet, and the default folder is inside the product's repository.
const ignoreFile = `# Written by shipward report new. Report cases describe vulnerabilities and incidents that may not be fixed or public
# yet, so git ignores this folder. In a private repository that should keep them, delete this file.
*
`

// IgnoreCases writes dir/.gitignore (ignore everything) when dir has none. It reports whether it wrote one.
func IgnoreCases(dir string) (bool, error) {
	path := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(ignoreFile), 0o644)
}

// TrackedWithRemote returns a remote's URL when caseDir is in a git repository that has a remote and git does not
// ignore the case's report.yaml, or "" (also when git is not installed). It runs git only locally; it asks no server.
func TrackedWithRemote(caseDir string) string {
	git, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(git, append([]string{"-C", caseDir}, args...)...).Output()
		return strings.TrimSpace(string(out)), err
	}
	if inside, err := run("rev-parse", "--is-inside-work-tree"); err != nil || inside != "true" {
		return ""
	}
	if _, err := run("check-ignore", "-q", "report.yaml"); err == nil {
		return "" // ignored
	}
	remotes, err := run("remote")
	if err != nil || remotes == "" {
		return ""
	}
	name := strings.Fields(remotes)[0]
	url, err := run("remote", "get-url", name)
	if err != nil || url == "" {
		return name
	}
	return name + ": " + withoutUser(url)
}

// withoutUser drops a user name and password from a URL (https://user:token@host/...), so no token reaches a log.
func withoutUser(url string) string {
	i := strings.Index(url, "://")
	if i < 0 {
		return url
	}
	rest := url[i+3:]
	host := rest
	if j := strings.Index(rest, "/"); j >= 0 {
		host = rest[:j]
	}
	if at := strings.LastIndex(host, "@"); at >= 0 {
		return url[:i+3] + rest[at+1:]
	}
	return url
}
