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
	"bufio"
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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
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
	out := runCliErr(t, "verify", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "entry in log cannot be located")

	// It should upload successfully.
	out = runCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Created entry at")

	// Now we should be able to verify it.
	out = runCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath, "--public-key", pubPath)
	outputContains(t, out, "Inclusion Proof:")
	outputContains(t, out, "Checkpoint:")
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

	env, err := signer.SignPayload(in_toto.PayloadType, b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	write(t, string(eb), attestationPath)
	write(t, sigx509.ECDSAPub, pubKeyPath)

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

	evps := []*sigx509.Verifier{}

	pb, _ := pem.Decode([]byte(sigx509.ECDSAPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signECDSA, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	evps = append(evps, &sigx509.Verifier{
		S: signECDSA,
	})

	pbRSA, _ := pem.Decode([]byte(sigx509.RSAKey))
	rsaPriv, err := x509.ParsePKCS8PrivateKey(pbRSA.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signRSA, err := signature.LoadRSAPKCS1v15Signer(rsaPriv.(*rsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	evps = append(evps, &sigx509.Verifier{
		S: signRSA,
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
	write(t, sigx509.ECDSAPub, ecdsapubKeyPath)
	write(t, sigx509.PubKey, rsapubKeyPath)

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

func TestSearchSHA512(t *testing.T) {
	sha512 := "c7694a1112ea1404a3c5852bdda04c2cc224b3567ef6ceb8204dbf2b382daacfc6837ee2ed9d5b82c90b880a3c7289778dbd5a8c2c08193459bcf7bd44581ed0"
	var out string
	out = runCli(t, "upload", "--type", "intoto:0.0.2",
		"--artifact", "envelope.sha512",
		"--pki-format", "x509",
		"--public-key", "test_sha512.pub")
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromTimestampOutput(t, out)
	out = runCli(t, "search", "--sha", fmt.Sprintf("sha512:%s", sha512))
	outputContains(t, out, uuid)
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

func TestVerifyNonExistantIndex(t *testing.T) {
	// this index is extremely likely to not exist
	out := runCliErr(t, "verify", "--log-index", "100000000")
	outputContains(t, out, "entry in log cannot be located")
}

func TestGetNonExistantUUID(t *testing.T) {
	// this uuid is extremely likely to not exist
	out := runCliErr(t, "get", "--uuid", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	outputContains(t, out, "404")
}

func TestVerifyNonExistantUUID(t *testing.T) {
	// this uuid is extremely likely to not exist
	out := runCliErr(t, "verify", "--uuid", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	outputContains(t, out, "entry in log cannot be located")

	// Check response code
	tid := getTreeID(t)
	h := sha256.Sum256([]byte("123"))
	entryID, err := sharding.CreateEntryIDFromParts(fmt.Sprintf("%x", tid),
		hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("{\"entryUUIDs\":[\"%s\"]}", entryID.ReturnEntryIDString())
	resp, err := http.Post("http://localhost:3000/api/v1/log/entries/retrieve",
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

func TestSearchQueryMalformedEntry(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadFile(filepath.Join(wd, "rekor.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("{\"entries\":[\"%s\"]}", b)
	resp, err := http.Post("http://localhost:3000/api/v1/log/entries/retrieve",
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d instead", resp.StatusCode)
	}
}

func TestSearchQueryNonExistentEntry(t *testing.T) {
	// Nonexistent but well-formed entry results in 404 not found.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadFile(filepath.Join(wd, "canonical_rekor.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("{\"entries\":[%s]}", b)
	t.Log(string(body))
	resp, err := http.Post("http://localhost:3000/api/v1/log/entries/retrieve",
		"application/json",
		bytes.NewBuffer([]byte(body)))
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
	// Not Found because currently we don't detect that an unused random tree ID is invalid.
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d instead", resp.StatusCode)
	}
	if strings.TrimSpace(string(c)) != "[]" {
		t.Fatalf("expected empty JSON array as response, got %s instead", string(c))
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
		rekorClient, err := client.GetRekorClient("http://localhost:3000", client.WithRetryCount(0))
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
					for entryID, _ := range entry {
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
