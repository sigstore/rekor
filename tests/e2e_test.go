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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/release-utils/version"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/types"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
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

func getUUIDFromTimestampOutput(t *testing.T, out string) string {
	t.Helper()
	// Output looks like "Created entry at index X, available at $URL/UUID", so grab the UUID:
	urlTokens := strings.Split(strings.TrimSpace(out), "\n")
	return getUUIDFromUploadOutput(t, urlTokens[len(urlTokens)-1])
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

func TestUploadVerifyRekord(t *testing.T) {

	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify should fail initially
	runCliErr(t, "verify", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)

	// It should upload successfully.
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")

	// Now we should be able to verify it.
	out = runCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Inclusion Proof:")
	outputContains(t, out, "Checkpoint:")
}

func TestUploadVerifyHashedRekord(t *testing.T) {

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

	// Now we should be able to verify it.
	out = runCli(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Inclusion Proof:")
	outputContains(t, out, "Checkpoint:")
}

func TestUploadVerifyRpm(t *testing.T) {

	// Create a random rpm and sign it.
	td := t.TempDir()
	rpmPath := filepath.Join(td, "rpm")

	createSignedRpm(t, rpmPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify should fail initially
	runCliErr(t, "verify", "--type=rpm", "--artifact", rpmPath, "--public-key", pubPath)

	// It should upload successfully.
	out := runCli(t, "upload", "--type=rpm", "--artifact", rpmPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")

	// Now we should be able to verify it.
	out = runCli(t, "verify", "--type=rpm", "--artifact", rpmPath, "--public-key", pubPath)
	outputContains(t, out, "Inclusion Proof:")
}

func TestLogInfo(t *testing.T) {
	// TODO: figure out some way to check the length, add something, and make sure the length increments!
	out := runCli(t, "loginfo")
	outputContains(t, out, "Verification Successful!")
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
	out = runCli(t, "get", "--format=json", "--uuid", entryID.ReturnEntryIDString())
}

func TestSearchNoEntriesRC1(t *testing.T) {
	runCliErr(t, "search", "--email", "noone@internetz.com")
}

func TestMinisign(t *testing.T) {
	// Create a keypair
	keyPath := filepath.Join(t.TempDir(), "minisign.key")
	pubPath := filepath.Join(t.TempDir(), "minisign.pub")

	// Set an empty password, we have to hit enter twice to confirm
	run(t, "\n\n", "minisign", "-G", "-s", keyPath, "-p", pubPath)

	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")
	createArtifact(t, artifactPath)

	// Send in one empty password over stdin
	out := run(t, "\n", "minisign", "-S", "-s", keyPath, "-m", artifactPath, "-x", sigPath)
	t.Log(out)

	// Now upload to the log!
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	outputContains(t, out, "Created entry at")

	uuidA := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	outputContains(t, out, "Inclusion Proof")

	out = runCli(t, "search", "--public-key", pubPath, "--pki-format", "minisign")
	outputContains(t, out, uuidA)

	// crease a second artifact and sign it
	artifactPath_B := filepath.Join(t.TempDir(), "artifact2")
	createArtifact(t, artifactPath_B)
	out = run(t, "\n", "minisign", "-S", "-s", keyPath, "-m", artifactPath_B, "-x", sigPath)
	// Now upload to the log!
	out = runCli(t, "upload", "--artifact", artifactPath_B, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	outputContains(t, out, "Created entry at")
	uuidB := getUUIDFromUploadOutput(t, out)

	tests := []struct {
		name               string
		expectedUuidACount int
		expectedUuidBCount int
		artifact           string
		operator           string
	}{
		{
			name:               "artifact A AND signature should return artifact A",
			expectedUuidACount: 1,
			expectedUuidBCount: 0,
			artifact:           artifactPath,
			operator:           "and",
		},
		{
			name:               "artifact A OR signature should return artifact A and B",
			expectedUuidACount: 1,
			expectedUuidBCount: 1,
			artifact:           artifactPath,
			operator:           "or",
		},
		{
			name:               "artifact B AND signature should return artifact B",
			expectedUuidACount: 0,
			expectedUuidBCount: 1,
			artifact:           artifactPath_B,
			operator:           "and",
		},
		{
			name:               "artifact B OR signature should return artifact A and B",
			expectedUuidACount: 1,
			expectedUuidBCount: 1,
			artifact:           artifactPath_B,
			operator:           "or",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out = runCli(t, "search", "--public-key", pubPath, "--pki-format", "minisign",
				"--operator", test.operator, "--artifact", test.artifact)

			expected := map[string]int{uuidA: test.expectedUuidACount, uuidB: test.expectedUuidBCount}
			actual := map[string]int{
				uuidA: strings.Count(out, uuidA),
				uuidB: strings.Count(out, uuidB),
			}
			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("expected to find %v, found %v", expected, actual)
			}
		})
	}
}

func TestSSH(t *testing.T) {
	td := t.TempDir()
	// Create a keypair
	keyPath := filepath.Join(td, "id_rsa")
	pubPath := filepath.Join(td, "id_rsa.pub")

	if err := ioutil.WriteFile(pubPath, []byte(sshPublicKey), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(keyPath, []byte(sshPrivateKey), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a random artifact and sign it.
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature.sig")
	artifact := createArtifact(t, artifactPath)

	sig := SSHSign(t, strings.NewReader(artifact))
	if err := ioutil.WriteFile(sigPath, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}

	// Now upload to the log!
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "ssh")
	outputContains(t, out, "Created entry at")

	uuid := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "ssh")
	outputContains(t, out, "Inclusion Proof")

	out = runCli(t, "search", "--public-key", pubPath, "--pki-format", "ssh")
	outputContains(t, out, uuid)
}

func TestJAR(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact.jar")

	createSignedJar(t, artifactPath)

	// If we do it twice, it should already exist
	out := runCli(t, "upload", "--artifact", artifactPath, "--type", "jar")
	outputContains(t, out, "Created entry at")
	out = runCli(t, "upload", "--artifact", artifactPath, "--type", "jar")
	outputContains(t, out, "Entry already exists")
}

func TestAPK(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact.apk")

	createSignedApk(t, artifactPath)

	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(pubKey), 0644); err != nil {
		t.Fatal(err)
	}

	// If we do it twice, it should already exist
	out := runCli(t, "upload", "--artifact", artifactPath, "--type", "alpine", "--public-key", pubPath)
	outputContains(t, out, "Created entry at")
	out = runCli(t, "upload", "--artifact", artifactPath, "--type", "alpine", "--public-key", pubPath)
	outputContains(t, out, "Entry already exists")
	// pass invalid public key, ensure we see an error with helpful message
	out = runCliErr(t, "upload", "--artifact", artifactPath, "--type", "alpine", "--public-key", artifactPath)
	outputContains(t, out, "invalid public key")
}

func TestIntoto(t *testing.T) {
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

	s, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := dsse.NewEnvelopeSigner(&verifier{
		s: s,
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := signer.SignPayload(in_toto.PayloadType, b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	write(t, string(eb), attestationPath)
	write(t, ecdsaPub, pubKeyPath)

	// ensure that we can't upload a intoto v0.0.1 entry
	v001out := runCliErr(t, "upload", "--artifact", attestationPath, "--type", "intoto:0.0.1", "--public-key", pubKeyPath)
	outputContains(t, v001out, "type intoto does not support version 0.0.1")

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

	out = runCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	outputContains(t, out, "Entry already exists")

}

func TestIntotoMultiSig(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	ecdsapubKeyPath := filepath.Join(td, "ecdsapub.pem")
	rsapubKeyPath := filepath.Join(td, "rsapub.pem")

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

	evps := []*verifier{}

	pb, _ := pem.Decode([]byte(ecdsaPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signECDSA, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	evps = append(evps, &verifier{
		s: signECDSA,
	})

	pbRSA, _ := pem.Decode([]byte(rsaKey))
	rsaPriv, err := x509.ParsePKCS8PrivateKey(pbRSA.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signRSA, err := signature.LoadRSAPKCS1v15Signer(rsaPriv.(*rsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	evps = append(evps, &verifier{
		s: signRSA,
	})

	signer, err := dsse.NewMultiEnvelopeSigner(2, evps[0], evps[1])
	if err != nil {
		t.Fatal(err)
	}

	env, err := signer.SignPayload(in_toto.PayloadType, b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	write(t, string(eb), attestationPath)
	write(t, ecdsaPub, ecdsapubKeyPath)
	write(t, pubKey, rsapubKeyPath)

	// ensure that we can't upload a intoto v0.0.1 entry
	v001out := runCliErr(t, "upload", "--artifact", attestationPath, "--type", "intoto:0.0.1", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	outputContains(t, v001out, "type intoto does not support version 0.0.1")

	// If we do it twice, it should already exist
	out := runCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "get", "--uuid", uuid, "--format=json")
	g := getOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	// The attestation should be stored at /var/run/attestations/$uuid

	got := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal([]byte(g.Attestation), &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(it, got); diff != "" {
		t.Errorf("diff: %s", diff)
	}

	attHash := sha256.Sum256([]byte(g.Attestation))

	intotoV002Model := &models.IntotoV002Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["IntotoObj"], intotoV002Model); err != nil {
		t.Errorf("could not convert body into intoto type: %v", err)
	}
	if intotoV002Model.Content.Hash == nil {
		t.Errorf("could not find hash over attestation %v", intotoV002Model)
	}
	recordedPayloadHash, err := hex.DecodeString(*intotoV002Model.Content.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting attestation hash to []byte: %v", err)
	}

	if !bytes.Equal(attHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("attestation hash %v doesnt match the payload we sent %v", hex.EncodeToString(attHash[:]),
			*intotoV002Model.Content.PayloadHash.Value))
	}

	out = runCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	outputContains(t, out, "Entry already exists")

}

func TestIntotoBlockV001(t *testing.T) {
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

	s, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := dsse.NewEnvelopeSigner(&verifier{
		s: s,
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := signer.SignPayload(in_toto.PayloadType, b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	uaString := fmt.Sprintf("rekor-cli/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)

	write(t, string(eb), attestationPath)
	write(t, ecdsaPub, pubKeyPath)

	rekorClient, err := client.GetRekorClient("http://localhost:3000", client.WithUserAgent(uaString))
	if err != nil {
		t.Fatal(err)
	}
	var entry models.ProposedEntry
	params := entries.NewCreateLogEntryParams()
	params.SetTimeout(time.Duration(30) * time.Second)

	props := &types.ArtifactProperties{}

	props.ArtifactPath = &url.URL{Path: attestationPath}

	collectedKeys := []*url.URL{{Path: pubKeyPath}}
	props.PublicKeyPaths = collectedKeys

	entry, err = types.NewProposedEntry(context.Background(), "intoto", "0.0.1", *props)
	if err != nil {
		t.Fatal(err)
	}
	params.SetProposedEntry(entry)

	_, err = rekorClient.Entries.CreateLogEntry(params)
	if err == nil {
		t.Fatal("insertion of v0.0.1 entry should fail")
	}
	if !strings.Contains(err.Error(), "entry kind 'intoto' does not support inserting entries of version '0.0.1'") {
		t.Errorf("Expected error as intoto v0.0.1 should not be allowed to be entered into rekor")
	}
}

func TestTimestampArtifact(t *testing.T) {
	var out string
	out = runCli(t, "upload", "--type", "rfc3161", "--artifact", "test.tsr")
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromTimestampOutput(t, out)

	artifactBytes, err := ioutil.ReadFile("test.tsr")
	if err != nil {
		t.Error(err)
	}
	sha := sha256.Sum256(artifactBytes)

	out = runCli(t, "upload", "--type", "rfc3161", "--artifact", "test.tsr")
	outputContains(t, out, "Entry already exists")

	out = runCli(t, "search", "--artifact", "test.tsr")
	outputContains(t, out, uuid)

	out = runCli(t, "search", "--sha", fmt.Sprintf("sha256:%s", hex.EncodeToString(sha[:])))
	outputContains(t, out, uuid)
}

func TestX509(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature")
	certPath := filepath.Join(td, "cert.pem")
	pubKeyPath := filepath.Join(td, "key.pem")

	createdX509SignedArtifact(t, artifactPath, sigPath)

	// Write the cert and public keys to disk as well
	if err := ioutil.WriteFile(certPath, []byte(rsaCert), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(pubKeyPath, []byte(pubKey), 0644); err != nil {
		t.Fatal(err)
	}

	// If we do it twice, it should already exist
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	outputContains(t, out, "Created entry at")
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	outputContains(t, out, "Entry already exists")

	// Now upload with the public key rather than the cert. They should NOT be deduped.
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	outputContains(t, out, "Created entry at")

	// Now let's go the other order to be sure. New artifact, key first then cert.
	createdX509SignedArtifact(t, artifactPath, sigPath)

	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	outputContains(t, out, "Created entry at")
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubKeyPath, "--pki-format", "x509")
	outputContains(t, out, "Entry already exists")
	// This should NOT already exist
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromUploadOutput(t, out)

	// Search via email
	out = runCli(t, "search", "--email", "test@rekor.dev")
	outputContains(t, out, uuid)

}

func TestUploadNoAPIKeyInOutput(t *testing.T) {
	// Create a random artifact and sign it.
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdPGPSignedArtifact(t, artifactPath, sigPath)

	// Write the public key to a file
	pubPath := filepath.Join(t.TempDir(), "pubKey.asc")
	if err := ioutil.WriteFile(pubPath, []byte(publicKey), 0644); err != nil {
		t.Fatal(err)
	}

	// It should upload successfully.
	out := runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath, "--api-key", "foobar")
	outputContains(t, out, "Created entry at")
	if strings.Contains(out, "foobar") {
		t.Errorf("CLI output contained API key when it should have squelched it")
	}
}

func TestWatch(t *testing.T) {

	td := t.TempDir()
	cmd := exec.Command(server, "watch", "--interval=1s")
	cmd.Env = append(os.Environ(), "REKOR_STH_BUCKET=file://"+td)
	go func() {
		b, err := cmd.CombinedOutput()
		t.Log(string(b))
		if cmd.ProcessState.Exited() && cmd.ProcessState.ExitCode() != 0 {
			if err != nil {
				t.Fatal(err)
			}
		}
	}()

	// Wait 3 intervals
	time.Sleep(3 * time.Second)
	cmd.Process.Kill()

	// Check for files
	fi, err := ioutil.ReadDir(td)
	if err != nil || len(fi) == 0 {
		t.Error("expected files")
	}
	fmt.Println(fi[0].Name())
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
	rekorPubKey, err := util.PublicKey(ctx, rekorClient)
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

func TestGetNonExistantIndex(t *testing.T) {
	// this index is extremely likely to not exist
	out := runCliErr(t, "get", "--log-index", "100000000")
	outputContains(t, out, "404")
}

func TestGetNonExistantUUID(t *testing.T) {
	// this uuid is extremely likely to not exist
	out := runCliErr(t, "get", "--uuid", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	outputContains(t, out, "404")
}

func TestEntryUpload(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	sigPath := filepath.Join(t.TempDir(), "signature.asc")

	createdPGPSignedArtifact(t, artifactPath, sigPath)
	payload, _ := ioutil.ReadFile(artifactPath)
	sig, _ := ioutil.ReadFile(sigPath)

	// Create the entry file
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
		t.Error(err)
	}

	if err := ioutil.WriteFile(entryPath, entryBytes, 0644); err != nil {
		t.Error(err)
	}

	// Now upload to rekor!
	out := runCli(t, "upload", "--entry", entryPath)
	outputContains(t, out, "Created entry at")
}

func TestTufVerifyUpload(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "timestamp.json")
	rootPath := filepath.Join(t.TempDir(), "root.json")

	createTufSignedArtifact(t, artifactPath, rootPath)

	// Now upload to rekor!
	out := runCli(t, "upload", "--artifact", artifactPath, "--public-key", rootPath, "--type", "tuf")
	outputContains(t, out, "Created entry at")

	uuid := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "verify", "--artifact", artifactPath, "--public-key", rootPath, "--type", "tuf")
	outputContains(t, out, "Inclusion Proof")

	out = runCli(t, "search", "--public-key", rootPath, "--pki-format", "tuf")
	outputContains(t, out, uuid)
}

// Regression test for https://github.com/sigstore/rekor/pull/956
// Requesting an inclusion proof concurrently with an entry write triggers
// a race where the inclusion proof returned does not verify because the
// tree head changes.
func TestInclusionProofRace(t *testing.T) {
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

	// Upload an entry
	runCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

	// Constantly uploads new signatures on an entry.
	var uploadRoutine = func(pubPath string) error {
		// Create a random artifact and sign it.
		artifactPath := filepath.Join(t.TempDir(), "artifact")
		sigPath := filepath.Join(t.TempDir(), "signature.asc")

		createdX509SignedArtifact(t, artifactPath, sigPath)
		dataBytes, _ := ioutil.ReadFile(artifactPath)
		h := sha256.Sum256(dataBytes)
		dataSHA := hex.EncodeToString(h[:])

		// Upload an entry
		out := runCli(t, "upload", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)
		outputContains(t, out, "Created entry at")

		return nil
	}

	// Attempts to verify the original entry.
	var verifyRoutine = func(dataSHA, sigPath, pubPath string) error {
		out := runCli(t, "verify", "--type=hashedrekord", "--pki-format=x509", "--artifact-hash", dataSHA, "--signature", sigPath, "--public-key", pubPath)

		if strings.Contains(out, "calculated root") || strings.Contains(out, "wrong") {
			return fmt.Errorf(out)
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

func TestHostnameInSTH(t *testing.T) {
	// get ID of container
	rekorContainerID := strings.Trim(run(t, "", "docker", "ps", "-q", "-f", "name=rekor-server"), "\n")
	resp, err := http.Get("http://localhost:3000/api/v1/log")
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
			resp, err := http.Post("http://localhost:3000/api/v1/log/entries/retrieve", "application/json", b)
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
	resp, err := http.Post("http://localhost:3000/api/v1/log/entries/retrieve", "application/json", bytes.NewBuffer([]byte(fmt.Sprintf(body, entryID.ReturnEntryIDString()))))
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
	resp, err = http.Post("http://localhost:3000/api/v1/log/entries/retrieve", "application/json", bytes.NewBuffer([]byte(fmt.Sprintf(body, entryID.ReturnEntryIDString()))))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 status code but got %d", resp.StatusCode)
	}
}
