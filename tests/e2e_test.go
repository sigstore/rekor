// +build e2e

package e2e

import (
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// createdSignedArtifact gets the test dir setup correctly with some random artifacts and keys.
func createdSignedArtifact(t *testing.T, artifactPath, sigPath string) {
	t.Helper()
	// First let's generate some random data so we don't have to worry about dupes.
	rand.Seed(time.Now().UnixNano())
	data := [100]byte{}
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}

	artifact := base64.StdEncoding.EncodeToString(data[:])
	// Write this to a file
	if err := ioutil.WriteFile(artifactPath, []byte(artifact), 0644); err != nil {
		t.Fatal(err)
	}

	// Sign it with our key and write that to a file
	signature := Sign(t, strings.NewReader(artifact))
	if err := ioutil.WriteFile(sigPath, []byte(signature), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicates(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Now upload to rekor!
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	if !strings.Contains(out, "Created entry at") {
		t.Errorf("Expected [Created entry at], got %s", out)
	}

	// Now upload the same one again, we should get a dupe entry.
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	if !strings.Contains(out, "Entry already exists") {
		t.Errorf("Expected [Entry already exists], got %s", out)
	}

	// Now do a new one, we should get a new entry
	createdSignedArtifact(t, artifactPath, sigPath)
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	if !strings.Contains(out, "Created entry at") {
		t.Errorf("Expected [Created entry at], got %s", out)
	}
}
