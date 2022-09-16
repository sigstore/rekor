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

package util

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"
)

var (
	cli         = "rekor-cli"
	server      = "rekor-server"
	nodeDataDir = "node"
)

func init() {

	p := os.Getenv("REKORTMPDIR")
	if p != "" {
		cli = path.Join(p, cli)
		server = path.Join(p, server)
	}
}

func OutputContains(t *testing.T, output, sub string) {
	t.Helper()
	if !strings.Contains(output, sub) {
		t.Errorf("Expected [%s] in response, got %s", sub, output)
	}
}

func Run(t *testing.T, stdin, cmd string, arg ...string) string {
	t.Helper()
	c := exec.Command(cmd, arg...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if os.Getenv("REKORTMPDIR") != "" {
		// ensure that we use a clean state.json file for each Run
		c.Env = append(c.Env, "HOME="+os.Getenv("REKORTMPDIR"))
	}
	b, err := c.CombinedOutput()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}

	return string(b)
}

func RunCli(t *testing.T, arg ...string) string {
	t.Helper()
	arg = append(arg, rekorServerFlag())
	// use a blank config file to ensure no collision
	if os.Getenv("REKORTMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("REKORTMPDIR")+".rekor.yaml")
	}
	return Run(t, "", cli, arg...)
}

func RunCliStdout(t *testing.T, arg ...string) string {
	t.Helper()
	arg = append(arg, rekorServerFlag())
	c := exec.Command(cli, arg...)

	if os.Getenv("REKORTMPDIR") != "" {
		// ensure that we use a clean state.json file for each Run
		c.Env = append(c.Env, "HOME="+os.Getenv("REKORTMPDIR"))
	}
	b, err := c.Output()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}
	return string(b)
}

func RunCliErr(t *testing.T, arg ...string) string {
	t.Helper()
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
	return string(b)
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

func readFile(t *testing.T, p string) string {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
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

func GetUUIDFromUploadOutput(t *testing.T, out string) string {
	t.Helper()
	// Output looks like "Artifact timestamped at ...\m Wrote response \n Created entry at index X, available at $URL/UUID", so grab the UUID:
	urlTokens := strings.Split(strings.TrimSpace(out), " ")
	url := urlTokens[len(urlTokens)-1]
	splitUrl := strings.Split(url, "/")
	return splitUrl[len(splitUrl)-1]
}
