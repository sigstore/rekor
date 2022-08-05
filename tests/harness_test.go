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
// +build e2e

package e2e

import (
	"bytes"
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
)

type StoredEntry struct {
	Attestation string
	UUID        string
}

// Make sure we can add an entry
func TestHarnessAddEntry(t *testing.T) {
	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdX509SignedArtifact(t, artifactPath, sigPath)
	dataBytes, _ := ioutil.ReadFile(artifactPath)
	h := sha256.Sum256(dataBytes)
	dataSHA := hex.EncodeToString(h[:])

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(rsaCert), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify should fail initially
	runCliErr(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

	// It should upload successfully.
	out := runCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromUploadOutput(t, out)

	// Now we should be able to verify it.
	out = runCli(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Inclusion Proof:")
	saveEntry(t, StoredEntry{UUID: uuid})
}

// Make sure we can add an intoto entry
func TestHarnessAddIntoto(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	pubKeyPath := filepath.Join(td, "pub.pem")

	// Get some random data so it's unique each run
	d := randomData(t, 10)
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

	pb, _ := pem.Decode([]byte(ecdsaPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dsse.NewEnvelopeSigner(&IntotoSigner{
		priv: priv.(*ecdsa.PrivateKey),
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

	write(t, string(eb), attestationPath)
	write(t, ecdsaPub, pubKeyPath)

	// If we do it twice, it should already exist
	out := runCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "get", "--uuid", uuid, "--format=json")
	g := getOut{}
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

	intotoModel := &models.IntotoV001Schema{}
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

	out = runCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	outputContains(t, out, "Entry already exists")
	saveEntry(t, StoredEntry{Attestation: g.Attestation, UUID: uuid})
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

func saveEntry(t *testing.T, entry StoredEntry) {
	file, attestations := getEntries(t)
	logIndex := activeTreeSize(t) - 1
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

func compareAttestation(t *testing.T, logIndex int, got string) {
	_, entries := getEntries(t)
	expected, ok := entries[logIndex]
	if !ok {
		t.Fatalf("expected to find persisted entries with logIndex %d but none existed: %v", logIndex, entries)
	}

	if got != expected.Attestation {
		t.Fatalf("attestations don't match, got %v expected %v", got, expected)
	}
}

// Make sure we can get and verify all entries
// For attestations, make sure we can see the attestation
func TestHarnessGetAllEntriesLogIndex(t *testing.T) {
	treeSize := activeTreeSize(t)
	if treeSize == 0 {
		t.Fatal("There are 0 entries in the log, there should be at least 2")
	}
	for i := 0; i < treeSize; i++ {
		out := runCli(t, "get", "--log-index", fmt.Sprintf("%d", i), "--format", "json")
		if !strings.Contains(out, "IntotoObj") {
			continue
		}
		var intotoObj struct {
			Attestation string
		}
		if err := json.Unmarshal([]byte(out), &intotoObj); err != nil {
			t.Fatal(err)
		}
		compareAttestation(t, i, intotoObj.Attestation)
		t.Log("IntotoObj matches stored attestation")
	}
}

func TestHarnessGetAllEntriesUUID(t *testing.T) {
	treeSize := activeTreeSize(t)
	if treeSize == 0 {
		t.Fatal("There are 0 entries in the log, there should be at least 2")
	}
	_, entries := getEntries(t)
	for _, e := range entries {
		outUUID := runCli(t, "get", "--uuid", e.UUID, "--format", "json")
		outEntryID := runCli(t, "get", "--uuid", entryID(t, e.UUID), "--format", "json")

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

func entryID(t *testing.T, uuid string) string {
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

func activeTreeSize(t *testing.T) int {
	out := runCliStdout(t, "loginfo", "--format", "json", "--store_tree_state", "false")
	t.Log(string(out))
	var s struct {
		ActiveTreeSize int
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	return s.ActiveTreeSize
}
