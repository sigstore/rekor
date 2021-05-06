//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build e2e

package e2e

import (
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	cli         = "../rekor-cli"
	server      = "../rekor-server"
	nodeDataDir = "node"
)

func outputContains(t *testing.T, output, sub string) {
	t.Helper()
	if !strings.Contains(output, sub) {
		t.Errorf("Expected [%s] in response, got %s", sub, output)
	}
}

func run(t *testing.T, stdin, cmd string, arg ...string) string {
	t.Helper()
	c := exec.Command(cmd, arg...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if os.Getenv("TMPDIR") != "" {
		// ensure that we use a clean state.json file for each run
		c.Env = append(c.Env, "HOME="+os.Getenv("TMPDIR"))
	}
	b, err := c.CombinedOutput()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}
	return string(b)
}

func runCli(t *testing.T, arg ...string) string {
	t.Helper()
	arg = append(arg, "--rekor_server=http://localhost:3000")
	// use a blank config file to ensure no collision
	if os.Getenv("TMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("TMPDIR")+".rekor.yaml")
	}
	return run(t, "", cli, arg...)
}

func runCliErr(t *testing.T, arg ...string) string {
	t.Helper()
	arg = append(arg, "--rekor_server=http://localhost:3000")
	// use a blank config file to ensure no collision
	if os.Getenv("TMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("TMPDIR")+".rekor.yaml")
	}
	cmd := exec.Command(cli, arg...)
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Log(string(b))
		t.Fatalf("expected error, got %s", string(b))
	}
	return string(b)
}

func readFile(t *testing.T, p string) string {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func randomData(n int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	data := make([]byte, n)
	if _, err := rand.Read(data[:]); err != nil {
		return nil, err
	}
	return data, nil
}

func createArtifact(t *testing.T, artifactPath string) string {
	t.Helper()
	// First let's generate some random data so we don't have to worry about dupes.
	data, err := randomData(100)
	if err != nil {
		t.Fatal(err)
	}

	artifact := base64.StdEncoding.EncodeToString(data[:])
	// Write this to a file
	if err := ioutil.WriteFile(artifactPath, []byte(artifact), 0644); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func extractLogEntry(t *testing.T, le models.LogEntry) models.LogEntryAnon {
	t.Helper()

	if len(le) != 1 {
		t.Fatal("expected length to be 1, is actually", len(le))
	}
	for _, v := range le {
		return v
	}
	// this should never happen
	return models.LogEntryAnon{}
}
