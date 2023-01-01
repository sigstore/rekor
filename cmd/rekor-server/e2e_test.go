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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/sigstore/rekor/pkg/sharding"

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
	t.Helper()
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
func TestEnvVariableValidation(t *testing.T) {
	os.Setenv("REKOR_FORMAT", "bogus")
	defer os.Unsetenv("REKOR_FORMAT")

	util.RunCliErr(t, "loginfo")
}
func TestGetCLI(t *testing.T) {
	// Create something and add it to the log
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")
	t.Cleanup(func() {
		os.Remove(artifactPath)
		os.Remove(sigPath)
	})
	util.CreatedPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(util.PubKey), 0644); err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		os.Remove(pubPath)
	})
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")

	uuid, err := sharding.GetUUIDFromIDString(util.GetUUIDFromUploadOutput(t, out))
	if err != nil {
		t.Error(err)
	}

	// since we at least have 1 valid entry, check the log at index 0
	util.RunCli(t, "get", "--log-index", "0")

	out = util.RunCli(t, "get", "--format=json", "--uuid", uuid)

	// The output here should be in JSON with this structure:
	g := util.GetOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Error(err)
	}

	if g.IntegratedTime == 0 {
		t.Errorf("Expected IntegratedTime to be set. Got %s", out)
	}
	// Get it with the logindex as well
	util.RunCli(t, "get", "--format=json", "--log-index", strconv.Itoa(g.LogIndex))

	// check index via the file and public key to ensure that the index has updated correctly
	out = util.RunCli(t, "search", "--artifact", artifactPath)
	util.OutputContains(t, out, uuid)

	out = util.RunCli(t, "search", "--public-key", pubPath)
	util.OutputContains(t, out, uuid)

	artifactBytes, err := ioutil.ReadFile(artifactPath)
	if err != nil {
		t.Error(err)
	}
	sha := sha256.Sum256(artifactBytes)

	out = util.RunCli(t, "search", "--sha", fmt.Sprintf("sha256:%s", hex.EncodeToString(sha[:])))
	util.OutputContains(t, out, uuid)

	// Exercise GET with the new EntryID (TreeID + UUID)
	tid := getTreeID(t)
	entryID, err := sharding.CreateEntryIDFromParts(fmt.Sprintf("%x", tid), uuid)
	if err != nil {
		t.Error(err)
	}
	out = util.RunCli(t, "get", "--format=json", "--uuid", entryID.ReturnEntryIDString())
}
func getTreeID(t *testing.T) int64 {
	t.Helper()
	out := util.RunCli(t, "loginfo")
	tidStr := strings.TrimSpace(strings.Split(out, "TreeID: ")[1])
	tid, err := strconv.ParseInt(tidStr, 10, 64)
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log("Tree ID:", tid)
	return tid
}
func TestSearchNoEntriesRC1(t *testing.T) {
	util.RunCliErr(t, "search", "--email", "noone@internetz.com")
}
func TestHostnameInSTH(t *testing.T) {
	// get ID of container
	rekorContainerID := strings.Trim(util.Run(t, "", "docker", "ps", "-q", "-f", "name=rekor-server"), "\n")
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/log", rekorServer()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(body), fmt.Sprintf(" %s ", rekorContainerID)) {
		t.Errorf("logInfo does not contain the hostname (%v) of the rekor-server container: %v", rekorContainerID, string(body))
	}
	if strings.Contains(string(body), "rekor.sigstore.dev") {
		t.Errorf("logInfo contains rekor.sigstore.dev which should not be set by default")
	}
}
func rekorServer() string {
	if s := os.Getenv("REKOR_SERVER"); s != "" {
		return s
	}
	return "http://localhost:3000"
}
func TestSearchSHA512(t *testing.T) {
	sha512 := "c7694a1112ea1404a3c5852bdda04c2cc224b3567ef6ceb8204dbf2b382daacfc6837ee2ed9d5b82c90b880a3c7289778dbd5a8c2c08193459bcf7bd44581ed0"
	var out string
	out = util.RunCli(t, "upload", "--type", "intoto:0.0.2",
		"--artifact", "tests/envelope.sha512",
		"--pki-format", "x509",
		"--public-key", "tests/test_sha512.pub")
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromTimestampOutput(t, out)
	out = util.RunCli(t, "search", "--sha", fmt.Sprintf("sha512:%s", sha512))
	util.OutputContains(t, out, uuid)
}
func TestVerifyNonExistentUUID(t *testing.T) {
	// this uuid is extremely likely to not exist
	out := util.RunCliErr(t, "verify", "--uuid", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	util.OutputContains(t, out, "entry in log cannot be located")

	// Check response code
	tid := getTreeID(t)
	h := sha256.Sum256([]byte("123"))
	entryID, err := sharding.CreateEntryIDFromParts(fmt.Sprintf("%x", tid),
		hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("{\"entryUUIDs\":[\"%s\"]}", entryID.ReturnEntryIDString())
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d instead", resp.StatusCode)
	}
	if strings.TrimSpace(string(c)) != "[]" {
		t.Fatalf("expected empty JSON array as response, got %s instead", string(c))
	}
}
func TestSearchQueryLimit(t *testing.T) {
	tests := []struct {
		description string
		limit       int
		shouldErr   bool
	}{
		{
			description: "request 6 entries",
			limit:       6,
		}, {
			description: "request 10 entries",
			limit:       10,
		}, {
			description: "request more than max",
			limit:       12,
			shouldErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			b := bytes.NewReader(getBody(t, test.limit))
			resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()), "application/json", b)
			if err != nil {
				t.Fatal(err)
			}
			c, _ := ioutil.ReadAll(resp.Body)
			t.Log(string(c))
			if resp.StatusCode != 200 && !test.shouldErr {
				t.Fatalf("expected test to pass but it failed")
			}
			if resp.StatusCode != 422 && test.shouldErr {
				t.Fatal("expected test to fail but it passed")
			}
			if test.shouldErr && !strings.Contains(string(c), "logIndexes in body should have at most 10 items") {
				t.Fatal("expected max limit error but didn't get it")
			}
		})
	}
}
func getBody(t *testing.T, limit int) []byte {
	t.Helper()
	s := fmt.Sprintf("{\"logIndexes\": [%d", limit)
	for i := 1; i < limit; i++ {
		s = fmt.Sprintf("%s, %d", s, i)
	}
	s += "]}"
	return []byte(s)
}
func TestSearchQueryMalformedEntry(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadFile(filepath.Join(wd, "tests/rekor.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("{\"entries\":[\"%s\"]}", b)
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d instead", resp.StatusCode)
	}
}
func entryID(t *testing.T, uuid string) string {
	t.Helper()
	if sharding.ValidateEntryID(uuid) == nil {
		return uuid
	}
	treeID, err := strconv.Atoi(os.Getenv("TREE_ID"))
	if err != nil {
		t.Fatal(err)
	}
	tid := strconv.FormatInt(int64(treeID), 16)
	ts, err := sharding.PadToTreeIDLen(tid)
	if err != nil {
		t.Fatal(err)
	}
	return ts + uuid
}
func TestHarnessGetAllEntriesUUID(t *testing.T) {
	if util.RekorCLIIncompatible() {
		t.Skipf("Skipping getting entries by UUID, old rekor-cli version %s is incompatible with server version %s", os.Getenv("CLI_VERSION"), os.Getenv("SERVER_VERSION"))
	}

	treeSize := util.ActiveTreeSize(t)
	if treeSize == 0 {
		t.Fatal("There are 0 entries in the log, there should be at least 2")
	}
	_, entries := util.GetEntries(t)

	for _, e := range entries {
		outUUID := util.RunCli(t, "get", "--uuid", e.UUID, "--format", "json")
		outEntryID := util.RunCli(t, "get", "--uuid", entryID(t, e.UUID), "--format", "json")

		if outUUID != outEntryID {
			t.Fatalf("Getting by uuid %s and entryID %s gave different outputs:\nuuid: %v\nentryID:%v\n", e.UUID, entryID(t, e.UUID), outUUID, outEntryID)
		}

		if !strings.Contains(outUUID, "IntotoObj") {
			continue
		}
		var intotoObj struct {
			Attestation string
		}
		if err := json.Unmarshal([]byte(outUUID), &intotoObj); err != nil {
			t.Fatal(err)
		}
		if intotoObj.Attestation != e.Attestation {
			t.Fatalf("attestations don't match, got %v expected %v", intotoObj.Attestation, e.Attestation)
		}
	}
}

// Make sure we can get and verify all entries
// For attestations, make sure we can see the attestation
// Older versions of the CLI may not be able to parse the retrieved entry.
func TestHarnessGetAllEntriesLogIndex(t *testing.T) {
	if util.RekorCLIIncompatible() {
		t.Skipf("Skipping getting entries by UUID, old rekor-cli version %s is incompatible with server version %s", os.Getenv("CLI_VERSION"), os.Getenv("SERVER_VERSION"))
	}

	treeSize := util.ActiveTreeSize(t)
	if treeSize == 0 {
		t.Fatal("There are 0 entries in the log, there should be at least 2")
	}
	for i := 0; i < treeSize; i++ {
		out := util.RunCli(t, "get", "--log-index", fmt.Sprintf("%d", i), "--format", "json")
		if !strings.Contains(out, "IntotoObj") {
			continue
		}
		var intotoObj struct {
			Attestation string
		}
		if err := json.Unmarshal([]byte(out), &intotoObj); err != nil {
			t.Fatal(err)
		}
		util.CompareAttestation(t, i, intotoObj.Attestation)
		t.Log("IntotoObj matches stored attestation")
	}
}

type StoredEntry struct {
	Attestation string
	UUID        string
}

// Make sure we can add an entry
func TestHarnessAddEntry(t *testing.T) {
	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	sigx509.CreatedX509SignedArtifact(t, artifactPath, sigPath)
	dataBytes, _ := ioutil.ReadFile(artifactPath)
	h := sha256.Sum256(dataBytes)
	dataSHA := hex.EncodeToString(h[:])

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(sigx509.RSACert), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify should fail initially
	util.RunCliErr(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

	// It should upload successfully.
	out := util.RunCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)
	logIndex := util.GetLogIndexFromUploadOutput(t, out)

	if !util.RekorCLIIncompatible() {
		// Now we should be able to verify it.
		out = util.RunCli(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
		util.OutputContains(t, out, "Inclusion Proof:")
	}

	saveEntry(t, logIndex, StoredEntry{UUID: uuid})
}

// Make sure we can add an intoto entry
func TestHarnessAddIntoto(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	pubKeyPath := filepath.Join(td, "pub.pem")

	// Get some random data so it's unique each run
	d := util.RandomData(t, 10)
	id := base64.StdEncoding.EncodeToString(d)

	it := in_toto.ProvenanceStatement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: slsa.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "foobar",
					Digest: slsa.DigestSet{
						"foo": "bar",
					},
				},
			},
		},
		Predicate: slsa.ProvenancePredicate{
			Builder: slsa.ProvenanceBuilder{
				ID: "foo" + id,
			},
		},
	}

	b, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}

	pb, _ := pem.Decode([]byte(sigx509.ECDSAPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	s, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := dsse.NewEnvelopeSigner(&sigx509.Verifier{
		S: s,
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	util.Write(t, string(eb), attestationPath)
	util.Write(t, sigx509.ECDSAPub, pubKeyPath)

	// If we do it twice, it should already exist
	out := util.RunCliStdout(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)
	logIndex := util.GetLogIndexFromUploadOutput(t, out)

	out = util.RunCli(t, "get", "--log-index", fmt.Sprintf("%d", logIndex), "--format=json")
	g := util.GetOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	// The attestation should be stored at /var/run/attestations/sha256:digest

	got := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal([]byte(g.Attestation), &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(it, got); diff != "" {
		t.Errorf("diff: %s", diff)
	}

	attHash := sha256.Sum256(b)

	intotoModel := &models.IntotoV002Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["IntotoObj"], intotoModel); err != nil {
		t.Errorf("could not convert body into intoto type: %v", err)
	}
	if intotoModel.Content == nil || intotoModel.Content.PayloadHash == nil {
		t.Errorf("could not find hash over attestation %v", intotoModel)
	}
	recordedPayloadHash, err := hex.DecodeString(*intotoModel.Content.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting attestation hash to []byte: %v", err)
	}

	if !bytes.Equal(attHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("attestation hash %v doesnt match the payload we sent %v", hex.EncodeToString(attHash[:]),
			*intotoModel.Content.PayloadHash.Value))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
	saveEntry(t, logIndex, StoredEntry{Attestation: g.Attestation, UUID: uuid})
}

func getEntries(t *testing.T) (string, map[int]StoredEntry) {
	tmpDir := os.Getenv("REKOR_HARNESS_TMPDIR")
	if tmpDir == "" {
		t.Skip("Skipping test, REKOR_HARNESS_TMPDIR is not set")
	}
	file := filepath.Join(tmpDir, "attestations")

	t.Log("Reading", file)
	attestations := map[int]StoredEntry{}
	contents, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) || contents == nil {
		return file, attestations
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &attestations); err != nil {
		t.Fatal(err)
	}
	return file, attestations
}

func saveEntry(t *testing.T, logIndex int, entry StoredEntry) {
	file, attestations := getEntries(t)
	t.Logf("Storing entry for logIndex %d", logIndex)
	attestations[logIndex] = entry
	contents, err := json.Marshal(attestations)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, contents, 0777); err != nil {
		t.Fatal(err)
	}
}
