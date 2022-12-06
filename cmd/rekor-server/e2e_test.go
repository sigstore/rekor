//
// Copyright 2022 The Sigstore Authors.
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

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/sigstore/rekor/pkg/util"
)

func TestDuplicates(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	util.CreatedPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(util.PubKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Now upload to rekor!
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")

	// Now upload the same one again, we should get a dupe entry.
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Entry already exists")

	// Now do a new one, we should get a new entry
	util.CreatedPGPSignedArtifact(t, artifactPath, sigPath)
	out = util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")
}

// Smoke test to ensure we're publishing and recording metrics when an API is
// called.
// TODO: use a more robust test approach here e.g. prometheus client-based?
// TODO: cover all endpoints to make sure none are dropped.
func TestMetricsCounts(t *testing.T) {
	latencyMetric := "rekor_latency_by_api_count{method=\"GET\",path=\"/api/v1/log\"}"
	qpsMetric := "rekor_qps_by_api{code=\"200\",method=\"GET\",path=\"/api/v1/log\"}"

	latencyCount, err := getRekorMetricCount(latencyMetric, t)
	if err != nil {
		t.Fatal(err)
	}

	qpsCount, err := getRekorMetricCount(qpsMetric, t)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get("http://localhost:3000/api/v1/log")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	latencyCount2, err := getRekorMetricCount(latencyMetric, t)
	if err != nil {
		t.Fatal(err)
	}

	qpsCount2, err := getRekorMetricCount(qpsMetric, t)
	if err != nil {
		t.Fatal(err)
	}

	if latencyCount2-latencyCount != 1 {
		t.Error("rekor_latency_by_api_count did not increment")
	}

	if qpsCount2-qpsCount != 1 {
		t.Error("rekor_qps_by_api did not increment")
	}
}
func getRekorMetricCount(metricLine string, t *testing.T) (int, error) {
	re, err := regexp.Compile(fmt.Sprintf("^%s.*([0-9]+)$", regexp.QuoteMeta(metricLine)))
	if err != nil {
		return 0, err
	}

	resp, err := http.Get("http://localhost:2112/metrics")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		match := re.FindStringSubmatch(scanner.Text())
		if len(match) != 2 {
			continue
		}

		result, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, nil
		}
		t.Log("Matched metric line: " + scanner.Text())
		return result, nil
	}
	return 0, nil
}
