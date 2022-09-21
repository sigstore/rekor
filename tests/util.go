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

//go:build e2e
// +build e2e

package e2e

import (
	"encoding/base64"
	"fmt"
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
	// Coverage flag must be the first arg passed to coverage binary
	// No impact when running with regular binary
	arg = append([]string{coverageFlag()}, arg...)
	c := exec.Command(cmd, arg...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if os.Getenv("REKORTMPDIR") != "" {
		// ensure that we use a clean state.json file for each run
		c.Env = append(c.Env, "HOME="+os.Getenv("REKORTMPDIR"))
	}
	b, err := c.CombinedOutput()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}

	// Remove test coverage output
	return strings.Split(strings.Split(string(b), "PASS")[0], "FAIL")[0]
}

func runCli(t *testing.T, arg ...string) string {
	t.Helper()
	arg = append(arg, rekorServerFlag())
	// use a blank config file to ensure no collision
	if os.Getenv("REKORTMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("REKORTMPDIR")+".rekor.yaml")
	}
	return run(t, "", cli, arg...)
}

func runCliStdout(t *testing.T, arg ...string) string {
	t.Helper()
	// Coverage flag must be the first arg passed to coverage binary
	// No impact when running with regular binary
	arg = append([]string{coverageFlag()}, arg...)
	arg = append(arg, rekorServerFlag())
	c := exec.Command(cli, arg...)

	if os.Getenv("REKORTMPDIR") != "" {
		// ensure that we use a clean state.json file for each run
		c.Env = append(c.Env, "HOME="+os.Getenv("REKORTMPDIR"))
	}
	b, err := c.Output()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}
	// Remove test coverage output
	return strings.Split(strings.Split(string(b), "PASS")[0], "FAIL")[0]
}

func runCliErr(t *testing.T, arg ...string) string {
	t.Helper()
	// Coverage flag must be the first arg passed to coverage binary
	// No impact when running with regular binary
	arg = append([]string{coverageFlag()}, arg...)
	arg = append(arg, rekorServerFlag())
	// use a blank config file to ensure no collision
	if os.Getenv("REKORTMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("REKORTMPDIR")+".rekor.yaml")
	}
	cmd := exec.Command(cli, arg...)
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Log(string(b))
		t.Fatalf("expected error, got %s", string(b))
	}
	// Remove test coverage output
	return strings.Split(strings.Split(string(b), "PASS")[0], "FAIL")[0]
}

func rekorServerFlag() string {
	return fmt.Sprintf("--rekor_server=%s", rekorServer())
}

func rekorServer() string {
	if s := os.Getenv("REKOR_SERVER"); s != "" {
		return s
	}
	return "http://localhost:3000"
}

func coverageFlag() string {
	return "-test.coverprofile=/tmp/rekor-cli."+randomSuffix(8)+".cov"
}

func readFile(t *testing.T, p string) string {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func randomSuffix(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func randomData(t *testing.T, n int) []byte {
	t.Helper()
	rand.Seed(time.Now().UnixNano())
	data := make([]byte, n)
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	return data
}

func createArtifact(t *testing.T, artifactPath string) string {
	t.Helper()
	// First let's generate some random data so we don't have to worry about dupes.
	data := randomData(t, 100)

	artifact := base64.StdEncoding.EncodeToString(data[:])
	// Write this to a file
	write(t, artifact, artifactPath)
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

func write(t *testing.T, data string, path string) {
	t.Helper()
	if err := ioutil.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}
