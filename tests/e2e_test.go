// +build e2e

package e2e

import (
	"io/ioutil"
	"os/exec"
	"strings"
	"testing"
)

const (
	cli         = "../rekor-cli"
	nodeDataDir = "node"
)

func runCli(t *testing.T, arg ...string) string {
	cmd := exec.Command(cli, arg...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}
	return string(b)
}

func runCliErr(t *testing.T, arg ...string) {
	cmd := exec.Command(cli, arg...)
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Log(string(b))
		t.Fatalf("expected error, got %s", string(b))
	}
}

func readFile(t *testing.T, p string) string {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestDuplicates(t *testing.T) {
	// Start with uploading the node data once
	out := runCli(t, "upload", "--artifact", readFile(t, "node/url"), "--sha", readFile(t, "node/sha"),
		"--signature=node/sig", "--public-key=node/key")
	if !strings.Contains(out, "Created entry at") {
		t.Errorf("Expected [Created entry at], got %s", out)
	}
	t.Log(out)

	// Now do it again, there should be a duplicate message
	out = runCli(t, "upload", "--artifact", readFile(t, "node/url"), "--sha", readFile(t, "node/sha"),
		"--signature=node/sig", "--public-key=node/key")
	if !strings.Contains(out, "Entry already exists") {
		t.Errorf("Expected [Entry already exists], got %s", out)
	}
	t.Log(out)
}
