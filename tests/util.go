// +build e2e

package e2e

import (
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	cli         = "../rekor-cli"
	nodeDataDir = "node"
)

func outputContains(t *testing.T, output, sub string) {
	t.Helper()
	if !strings.Contains(output, sub) {
		t.Errorf("Expected [%s] in response, got %s", sub, output)
	}
}

func runCli(t *testing.T, arg ...string) string {
	t.Helper()
	cmd := exec.Command(cli, arg...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}
	return string(b)
}

func runCliErr(t *testing.T, arg ...string) {
	t.Helper()
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
