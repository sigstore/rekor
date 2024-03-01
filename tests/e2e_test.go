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

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"cloud.google.com/go/pubsub"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/rekor/pkg/client"
	generatedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
	"github.com/sigstore/rekor/pkg/generated/models"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func getUUIDFromUploadOutput(t *testing.T, out string) string {
	t.Helper()
	// Output looks like "Artifact timestamped at ...\m Wrote response \n Created entry at index X, available at $URL/UUID", so grab the UUID:
	urlTokens := strings.Split(strings.TrimSpace(out), " ")
	url := urlTokens[len(urlTokens)-1]
	splitUrl := strings.Split(url, "/")
	return splitUrl[len(splitUrl)-1]
}

func getLogIndexFromUploadOutput(t *testing.T, out string) int {
	t.Helper()
	t.Log(out)
	// Output looks like "Created entry at index X, available at $URL/UUID", so grab the index X:
	split := strings.Split(strings.TrimSpace(out), ",")
	ss := strings.Split(split[0], " ")
	i, err := strconv.Atoi(ss[len(ss)-1])
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestEnvVariableValidation(t *testing.T) {
	os.Setenv("REKOR_FORMAT", "bogus")
	defer os.Unsetenv("REKOR_FORMAT")

	runCliErr(t, "loginfo")
}

func TestDuplicates(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Now upload to rekor!
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")

	// Now upload the same one again, we should get a dupe entry.
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Entry already exists")

	// Now do a new one, we should get a new entry
	createdPGPSignedArtifact(t, artifactPath, sigPath)
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")
}

type getOut struct {
	Attestation     string
	AttestationType string
	Body            interface{}
	LogIndex        int
	IntegratedTime  int64
}

func TestGetCLI(t *testing.T) {
	// Create something and add it to the log
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")

	uuid, err := sharding.GetUUIDFromIDString(getUUIDFromUploadOutput(t, out))
	if err != nil {
		t.Error(err)
	}

	// since we at least have 1 valid entry, check the log at index 0
	runCli(t, "get", "--log-index", "0")

	out = runCli(t, "get", "--format=json", "--uuid", uuid)

	// The output here should be in JSON with this structure:
	g := getOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Error(err)
	}

	if g.IntegratedTime == 0 {
		t.Errorf("Expected IntegratedTime to be set. Got %s", out)
	}
	// Get it with the logindex as well
	runCli(t, "get", "--format=json", "--log-index", strconv.Itoa(g.LogIndex))

	// check index via the file and public key to ensure that the index has updated correctly
	out = runCli(t, "search", "--artifact", artifactPath)
	outputContains(t, out, uuid)

	out = runCli(t, "search", "--public-key", pubPath)
	outputContains(t, out, uuid)

	artifactBytes, err := ioutil.ReadFile(artifactPath)
	if err != nil {
		t.Error(err)
	}
	sha := sha256.Sum256(artifactBytes)

	out = runCli(t, "search", "--sha", fmt.Sprintf("sha256:%s", hex.EncodeToString(sha[:])))
	outputContains(t, out, uuid)

	// Exercise GET with the new EntryID (TreeID + UUID)
	tid := getTreeID(t)
	entryID, err := sharding.CreateEntryIDFromParts(fmt.Sprintf("%x", tid), uuid)
	if err != nil {
		t.Error(err)
	}
	runCli(t, "get", "--format=json", "--uuid", entryID.ReturnEntryIDString())
}

func publicKeyFromRekorClient(ctx context.Context, c *generatedClient.Rekor) (*ecdsa.PublicKey, error) {
	resp, err := c.Pubkey.GetPublicKey(&pubkey.GetPublicKeyParams{Context: ctx})
	if err != nil {
		return nil, err
	}

	// marshal the pubkey
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(resp.GetPayload()))
	if err != nil {
		return nil, err
	}
	ed, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key retrieved from Rekor is not an ECDSA key")
	}
	return ed, nil
}

func TestSignedEntryTimestamp(t *testing.T) {
	// Create a random payload and sign it
	ctx := context.Background()
	payload := []byte("payload")
	s, err := signer.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignMessage(bytes.NewReader(payload), options.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := s.PublicKey(options.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pubkey)
	if err != nil {
		t.Fatal(err)
	}

	// submit our newly signed payload to rekor
	rekorClient, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Fatal(err)
	}

	re := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(payload),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: (*strfmt.Base64)(&sig),
				Format:  swag.String(models.RekordV001SchemaSignatureFormatX509),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: (*strfmt.Base64)(&pemBytes),
				},
			},
		},
	}

	returnVal := models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}
	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(&returnVal)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		t.Fatal(err)
	}
	logEntry := extractLogEntry(t, resp.GetPayload())

	// verify the signature against the log entry (without the signature)
	timestampSig := logEntry.Verification.SignedEntryTimestamp
	logEntry.Verification = nil
	payload, err = logEntry.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		t.Fatal(err)
	}
	// get rekor's public key
	rekorPubKey, err := publicKeyFromRekorClient(ctx, rekorClient)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := signature.LoadVerifier(rekorPubKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(timestampSig), bytes.NewReader(canonicalized), options.WithContext(ctx)); err != nil {
		t.Fatal("unable to verify")
	}
}

func TestEntryUpload(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	// Create the entry file
	createdPGPSignedArtifact(t, artifactPath, sigPath)
	payload, err := ioutil.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ioutil.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}

	entryPath := filepath.Join(t.TempDir(), "entry.json")
	pubKeyBytes := []byte(publicKey)

	re := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(payload),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: (*strfmt.Base64)(&sig),
				Format:  swag.String(models.RekordV001SchemaSignatureFormatPgp),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: (*strfmt.Base64)(&pubKeyBytes),
				},
			},
		},
	}

	returnVal := models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}
	entryBytes, err := json.Marshal(returnVal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(entryPath, entryBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Start pubsub client to capture notifications. Values match those in
	// docker-compose.test.yml.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	psc, err := pubsub.NewClient(ctx, "test-project")
	if err != nil {
		t.Fatalf("Create pubsub client: %v", err)
	}
	topic, err := psc.CreateTopic(ctx, "new-entry")
	if err != nil {
		// Assume error is AlreadyExists if one occurrs unless it is context timeout.
		// If the error was not AlreadyExists, it will be caught in later error
		// checks in this test.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Create pubsub topic: %v", err)
		}
		topic = psc.Topic("new-entry")
	}
	filters := []string{
		`attributes:rekor_entry_kind`,                          // Ignore any messages that do not have this attribute
		`attributes.rekor_signing_subjects = "test@rekor.dev"`, // This is the email in the hard-coded PGP test key
		`attributes.datacontenttype = "application/json"`,      // Only fetch the JSON formatted events
	}
	cfg := pubsub.SubscriptionConfig{
		Topic:  topic,
		Filter: strings.Join(filters, " AND "),
	}
	sub, err := psc.CreateSubscription(ctx, "new-entry-sub", cfg)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Create pubsub subscription: %v", err)
		}
		sub = psc.Subscription("new-entry-sub")
	}
	ch := make(chan []byte, 1)
	go func() {
		if err := sub.Receive(ctx, func(_ context.Context, m *pubsub.Message) {
			ch <- m.Data
		}); err != nil {
			t.Errorf("Receive pubusub msg: %v", err)
		}
	}()

	// Now upload to rekor!
	out := runCli(t, "upload", "--entry", entryPath)
	outputContains(t, out, "Created entry at")

	// Await pubsub
	select {
	case msg := <-ch:
		t.Logf("Got pubsub message!\n%s", string(msg))
	case <-ctx.Done():
		t.Errorf("Did not receive pubsub message: %v", ctx.Err())
	}
}

// Regression test for https://github.com/sigstore/rekor/pull/956
// Requesting an inclusion proof concurrently with an entry write triggers
// a race where the inclusion proof returned does not verify because the
// tree head changes.
func TestInclusionProofRace(t *testing.T) {
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

	// Upload an entry
	runCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

	// Constantly uploads new signatures on an entry.
	uploadRoutine := func(pubPath string) error {
		// Create a random artifact and sign it.
		artifactPath := filepath.Join(t.TempDir(), "artifact")
		sigPath := filepath.Join(t.TempDir(), "signature.asc")

		sigx509.CreatedX509SignedArtifact(t, artifactPath, sigPath)
		dataBytes, _ := ioutil.ReadFile(artifactPath)
		h := sha256.Sum256(dataBytes)
		dataSHA := hex.EncodeToString(h[:])

		// Upload an entry
		out := runCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
		outputContains(t, out, "Created entry at")

		return nil
	}

	// Attempts to verify the original entry.
	verifyRoutine := func(dataSHA, sigPath, pubPath string) error {
		out := runCli(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

		if strings.Contains(out, "calculated root") || strings.Contains(out, "wrong") {
			return errors.New(out)
		}

		return nil
	}

	var g errgroup.Group
	for i := 0; i < 50; i++ {
		g.Go(func() error { return uploadRoutine(pubPath) })
		g.Go(func() error { return verifyRoutine(dataSHA, sigPath, pubPath) })
	}

	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
}

// TestIssue1308 should be run once before any other tests (against an empty log)
func TestIssue1308(t *testing.T) {
	// we run this to validate issue 1308 which needs to be tested against an empty log
	if getTotalTreeSize(t) == 0 {
		TestSearchQueryNonExistentEntry(t)
	} else {
		t.Skip("skipping because log is not empty")
	}
}

func TestSearchQueryNonExistentEntry(t *testing.T) {
	// Nonexistent but well-formed entry results in 200 with empty array as body
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadFile(filepath.Join(wd, "canonical_rekor.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("{\"entries\":[%s]}", b)
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d instead: %v", resp.StatusCode, string(c))
	}
	if strings.TrimSpace(string(c)) != "[]" {
		t.Fatalf("expected empty JSON array as response, got %s instead", string(c))
	}
}

func getTreeID(t *testing.T) int64 {
	out := runCli(t, "loginfo")
	tidStr := strings.TrimSpace(strings.Split(out, "TreeID: ")[1])
	tid, err := strconv.ParseInt(tidStr, 10, 64)
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log("Tree ID:", tid)
	return tid
}

func getTotalTreeSize(t *testing.T) int64 {
	out := runCli(t, "loginfo")
	sizeStr := strings.Fields(strings.Split(out, "Total Tree Size: ")[1])[0]
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log("Total Tree Size:", size)
	return size
}

// This test confirms that we validate tree ID when using the /api/v1/log/entries/retrieve endpoint
// https://github.com/sigstore/rekor/issues/1014
func TestSearchValidateTreeID(t *testing.T) {
	// Create something and add it to the log
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")

	uuid, err := sharding.GetUUIDFromIDString(getUUIDFromUploadOutput(t, out))
	if err != nil {
		t.Error(err)
	}
	// Make sure we can get by Entry ID
	tid := getTreeID(t)
	entryID, err := sharding.CreateEntryIDFromParts(fmt.Sprintf("%x", tid), uuid)
	if err != nil {
		t.Fatal(err)
	}
	body := "{\"entryUUIDs\":[\"%s\"]}"
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()), "application/json", bytes.NewBuffer([]byte(fmt.Sprintf(body, entryID.ReturnEntryIDString()))))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 status code but got %d", resp.StatusCode)
	}

	// Make sure we fail with a random tree ID
	fakeTID := tid + 1
	entryID, err = sharding.CreateEntryIDFromParts(fmt.Sprintf("%x", fakeTID), uuid)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()), "application/json", bytes.NewBuffer([]byte(fmt.Sprintf(body, entryID.ReturnEntryIDString()))))
	if err != nil {
		t.Fatal(err)
	}
	// Not Found because currently we don't detect that an unused random tree ID is invalid.
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d instead", resp.StatusCode)
	}
	if strings.TrimSpace(string(c)) != "[]" {
		t.Fatalf("expected empty JSON array as response, got %s instead", string(c))
	}
}

// TestSearchLogQuerySingleShard provides coverage testing on the searchLogQuery endpoint within a single shard
func TestSearchLogQuerySingleShard(t *testing.T) {

	// Write the shared public key to a file
	pubPath := filepath.Join(t.TempDir(), "logQuery_pubKey.asc")
	pubKeyBytes := []byte(publicKey)
	if err := ioutil.WriteFile(pubPath, pubKeyBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Create two valid log entries to use for the test cases
	firstArtifactPath := filepath.Join(t.TempDir(), "artifact1")
	firstSigPath := filepath.Join(t.TempDir(), "signature1.asc")
	createdPGPSignedArtifact(t, firstArtifactPath, firstSigPath)
	firstArtifactBytes, _ := ioutil.ReadFile(firstArtifactPath)
	firstSigBytes, _ := ioutil.ReadFile(firstSigPath)

	firstRekord := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(firstArtifactBytes),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: (*strfmt.Base64)(&firstSigBytes),
				Format:  swag.String(models.RekordV001SchemaSignatureFormatPgp),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: (*strfmt.Base64)(&pubKeyBytes),
				},
			},
		},
	}
	firstEntry := &models.Rekord{
		APIVersion: swag.String(firstRekord.APIVersion()),
		Spec:       firstRekord.RekordObj,
	}

	secondArtifactPath := filepath.Join(t.TempDir(), "artifact2")
	secondSigPath := filepath.Join(t.TempDir(), "signature2.asc")
	createdPGPSignedArtifact(t, secondArtifactPath, secondSigPath)
	secondArtifactBytes, _ := ioutil.ReadFile(secondArtifactPath)
	secondSigBytes, _ := ioutil.ReadFile(secondSigPath)

	secondRekord := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(secondArtifactBytes),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: (*strfmt.Base64)(&secondSigBytes),
				Format:  swag.String(models.RekordV001SchemaSignatureFormatPgp),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: (*strfmt.Base64)(&pubKeyBytes),
				},
			},
		},
	}
	secondEntry := &models.Rekord{
		APIVersion: swag.String(secondRekord.APIVersion()),
		Spec:       secondRekord.RekordObj,
	}

	// Now upload them to rekor!
	firstOut := runCli(t, "upload", "--artifact", firstArtifactPath, "--signature", firstSigPath, "--public-key", pubPath)
	secondOut := runCli(t, "upload", "--artifact", secondArtifactPath, "--signature", secondSigPath, "--public-key", pubPath)

	firstEntryID := getUUIDFromUploadOutput(t, firstOut)
	firstUUID, _ := sharding.GetUUIDFromIDString(firstEntryID)
	firstIndex := int64(getLogIndexFromUploadOutput(t, firstOut))
	secondEntryID := getUUIDFromUploadOutput(t, secondOut)
	secondUUID, _ := sharding.GetUUIDFromIDString(secondEntryID)
	secondIndex := int64(getLogIndexFromUploadOutput(t, secondOut))

	// this is invalid because treeID is > int64
	invalidEntryID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeeefff"
	invalidIndex := int64(-1)
	invalidEntry := &models.Rekord{
		APIVersion: swag.String(secondRekord.APIVersion()),
	}

	nonexistentArtifactPath := filepath.Join(t.TempDir(), "artifact3")
	nonexistentSigPath := filepath.Join(t.TempDir(), "signature3.asc")
	createdPGPSignedArtifact(t, nonexistentArtifactPath, nonexistentSigPath)
	nonexistentArtifactBytes, _ := ioutil.ReadFile(nonexistentArtifactPath)
	nonexistentSigBytes, _ := ioutil.ReadFile(nonexistentSigPath)

	nonexistentEntryID := "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeeefff"
	nonexistentUUID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeeefff"
	nonexistentIndex := int64(999999999) // assuming we don't put that many entries in the log
	nonexistentRekord := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(nonexistentArtifactBytes),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: (*strfmt.Base64)(&nonexistentSigBytes),
				Format:  swag.String(models.RekordV001SchemaSignatureFormatPgp),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: (*strfmt.Base64)(&pubKeyBytes),
				},
			},
		},
	}
	nonexistentEntry := &models.Rekord{
		APIVersion: swag.String("0.0.1"),
		Spec:       nonexistentRekord.RekordObj,
	}

	type testCase struct {
		name                      string
		expectSuccess             bool
		expectedErrorResponseCode int64
		expectedEntryIDs          []string
		entryUUIDs                []string
		logIndexes                []*int64
		entries                   []models.ProposedEntry
	}

	testCases := []testCase{
		{
			name:             "empty entryUUIDs",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			entryUUIDs:       []string{},
		},
		{
			name:             "first in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			entryUUIDs:       []string{firstEntryID},
		},
		{
			name:             "first in log (using UUID in entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			entryUUIDs:       []string{firstUUID},
		},
		{
			name:             "second in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{secondEntryID},
			entryUUIDs:       []string{secondEntryID},
		},
		{
			name:                      "invalid entryID (using entryUUIDs)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusBadRequest,
			entryUUIDs:                []string{invalidEntryID},
		},
		{
			name:             "valid entryID not in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			entryUUIDs:       []string{nonexistentEntryID},
		},
		{
			name:             "valid UUID not in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			entryUUIDs:       []string{nonexistentUUID},
		},
		{
			name:             "both valid entries in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{firstEntryID, secondEntryID},
		},
		{
			name:             "both valid entries in log (one with UUID, other with entryID) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{firstEntryID, secondUUID},
		},
		{
			name:                      "one valid entry in log, one malformed (using entryUUIDs)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusBadRequest,
			entryUUIDs:                []string{firstEntryID, invalidEntryID},
		},
		{
			name:             "one existing, one valid entryID but not in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			entryUUIDs:       []string{firstEntryID, nonexistentEntryID},
		},
		{
			name:             "two existing, one valid entryID but not in log (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{firstEntryID, secondEntryID, nonexistentEntryID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 1) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{firstEntryID, nonexistentEntryID, secondEntryID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 2) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{nonexistentEntryID, firstEntryID, secondEntryID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 3) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{nonexistentUUID, firstEntryID, secondEntryID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 4) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{nonexistentEntryID, firstUUID, secondEntryID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 5) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{nonexistentEntryID, firstEntryID, secondUUID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 6) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{nonexistentUUID, firstEntryID, secondUUID},
		},
		{
			name:             "two existing, one valid entryID but not in log (different ordering 7) (using entryUUIDs)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entryUUIDs:       []string{nonexistentEntryID, firstUUID, secondUUID},
		},
		{
			name:                      "request more than 10 entries (using entryUUIDs)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			entryUUIDs:                []string{firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID, firstEntryID},
		},
		{
			name:             "empty logIndexes",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			logIndexes:       []*int64{},
		},
		{
			name:             "first in log (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			logIndexes:       []*int64{&firstIndex},
		},
		{
			name:             "second in log (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{secondEntryID},
			logIndexes:       []*int64{&secondIndex},
		},
		{
			name:                      "invalid logIndex (using logIndexes)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			logIndexes:                []*int64{&invalidIndex},
		},
		{
			name:             "valid index not in log (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			logIndexes:       []*int64{&nonexistentIndex},
		},
		{
			name:             "both valid entries in log (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			logIndexes:       []*int64{&firstIndex, &secondIndex},
		},
		{
			name:                      "one valid entry in log, one malformed (using logIndexes)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			logIndexes:                []*int64{&firstIndex, &invalidIndex},
		},
		{
			name:             "one existing, one valid Index but not in log (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			logIndexes:       []*int64{&firstIndex, &nonexistentIndex},
		},
		{
			name:             "two existing, one valid Index but not in log (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			logIndexes:       []*int64{&firstIndex, &secondIndex, &nonexistentIndex},
		},
		{
			name:             "two existing, one valid Index but not in log (different ordering 1) (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			logIndexes:       []*int64{&firstIndex, &nonexistentIndex, &secondIndex},
		},
		{
			name:             "two existing, one valid Index but not in log (different ordering 2) (using logIndexes)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			logIndexes:       []*int64{&nonexistentIndex, &firstIndex, &secondIndex},
		},
		{
			name:                      "request more than 10 entries (using logIndexes)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			logIndexes:                []*int64{&firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex, &firstIndex},
		},
		{
			name:             "empty entries",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			entries:          []models.ProposedEntry{},
		},
		{
			name:             "first in log (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			entries:          []models.ProposedEntry{firstEntry},
		},
		{
			name:             "second in log (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{secondEntryID},
			entries:          []models.ProposedEntry{secondEntry},
		},
		{
			name:                      "invalid entry (using entries)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			entries:                   []models.ProposedEntry{invalidEntry},
		},
		{
			name:             "valid entry not in log (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{},
			entries:          []models.ProposedEntry{nonexistentEntry},
		},
		{
			name:             "both valid entries in log (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entries:          []models.ProposedEntry{firstEntry, secondEntry},
		},
		{
			name:                      "one valid entry in log, one malformed (using entries)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			entries:                   []models.ProposedEntry{firstEntry, invalidEntry},
		},
		{
			name:             "one existing, one valid Index but not in log (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID},
			entries:          []models.ProposedEntry{firstEntry, nonexistentEntry},
		},
		{
			name:             "two existing, one valid Index but not in log (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entries:          []models.ProposedEntry{firstEntry, secondEntry, nonexistentEntry},
		},
		{
			name:             "two existing, one valid Index but not in log (different ordering 1) (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entries:          []models.ProposedEntry{firstEntry, nonexistentEntry, secondEntry},
		},
		{
			name:             "two existing, one valid Index but not in log (different ordering 2) (using entries)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID},
			entries:          []models.ProposedEntry{nonexistentEntry, firstEntry, secondEntry},
		},
		{
			name:                      "request more than 10 entries (using entries)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			entries:                   []models.ProposedEntry{firstEntry, firstEntry, firstEntry, firstEntry, firstEntry, firstEntry, firstEntry, firstEntry, firstEntry, firstEntry, firstEntry},
		},
		{
			name:                      "request more than 10 entries (using mixture)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			entryUUIDs:                []string{firstEntryID, firstEntryID, firstEntryID, firstEntryID},
			logIndexes:                []*int64{&firstIndex, &firstIndex, &firstIndex},
			entries:                   []models.ProposedEntry{firstEntry, firstEntry, firstEntry, firstEntry},
		},
		{
			name:                      "request valid and invalid (using mixture)",
			expectSuccess:             false,
			expectedErrorResponseCode: http.StatusUnprocessableEntity,
			entryUUIDs:                []string{firstEntryID, firstEntryID, firstEntryID, firstEntryID},
			logIndexes:                []*int64{&invalidIndex, &invalidIndex, &invalidIndex},
			entries:                   []models.ProposedEntry{firstEntry, firstEntry, firstEntry},
		},
		{
			name:             "request valid and nonexistent (using mixture)",
			expectSuccess:    true,
			expectedEntryIDs: []string{firstEntryID, secondEntryID, firstEntryID, secondEntryID, firstEntryID, secondEntryID},
			entryUUIDs:       []string{firstEntryID, secondEntryID, nonexistentEntryID},
			logIndexes:       []*int64{&firstIndex, &secondIndex, &nonexistentIndex},
			entries:          []models.ProposedEntry{firstEntry, secondEntry, nonexistentEntry},
		},
	}

	for _, test := range testCases {
		rekorClient, err := client.GetRekorClient(rekorServer(), client.WithRetryCount(0))
		if err != nil {
			t.Fatal(err)
		}
		t.Run(test.name, func(t *testing.T) {
			params := entries.NewSearchLogQueryParams()
			entry := &models.SearchLogQuery{}
			if len(test.entryUUIDs) > 0 {
				t.Log("trying with entryUUIDs: ", test.entryUUIDs)
				entry.EntryUUIDs = test.entryUUIDs
			}
			if len(test.logIndexes) > 0 {
				entry.LogIndexes = test.logIndexes
			}
			if len(test.entries) > 0 {
				entry.SetEntries(test.entries)
			}
			params.SetEntry(entry)

			resp, err := rekorClient.Entries.SearchLogQuery(params)
			if err != nil {
				if !test.expectSuccess {
					if _, ok := err.(*entries.SearchLogQueryBadRequest); ok {
						if test.expectedErrorResponseCode != http.StatusBadRequest {
							t.Fatalf("unexpected error code received: expected %d, got %d: %v", test.expectedErrorResponseCode, http.StatusBadRequest, err)
						}
					} else if _, ok := err.(*entries.SearchLogQueryUnprocessableEntity); ok {
						if test.expectedErrorResponseCode != http.StatusUnprocessableEntity {
							t.Fatalf("unexpected error code received: expected %d, got %d: %v", test.expectedErrorResponseCode, http.StatusUnprocessableEntity, err)
						}
					} else if e, ok := err.(*entries.SearchLogQueryDefault); ok {
						t.Fatalf("unexpected error: %v", e)
					}
				} else {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if len(resp.Payload) != len(test.expectedEntryIDs) {
					t.Fatalf("unexpected number of responses received: expected %d, got %d", len(test.expectedEntryIDs), len(resp.Payload))
				}
				// walk responses, build up list of returned entry IDs
				returnedEntryIDs := []string{}
				for _, entry := range resp.Payload {
					// do this for dynamic keyed entries
					for entryID := range entry {
						t.Log("received entry: ", entryID)
						returnedEntryIDs = append(returnedEntryIDs, entryID)
					}
				}
				// we have the expected number of responses, let's ensure they're the ones we expected
				if out := cmp.Diff(returnedEntryIDs, test.expectedEntryIDs, cmpopts.SortSlices(func(a, b string) bool { return a < b })); out != "" {
					t.Fatalf("unexpected responses: %v", out)
				}
			}
		})
	}
}
