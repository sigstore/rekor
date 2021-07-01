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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/pkg/ssl"
	"github.com/sigstore/rekor/pkg/client"
	genclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/timestamp"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/signer"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
)

func getUUIDFromUploadOutput(t *testing.T, out string) string {
	t.Helper()
	// Output looks like "Artifact timestamped at ...\m Wrote response \n Created entry at index X, available at $URL/UUID", so grab the UUID:
	urlTokens := strings.Split(strings.TrimSpace(out), " ")
	url := urlTokens[len(urlTokens)-1]
	splitUrl := strings.Split(url, "/")
	return splitUrl[len(splitUrl)-1]
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

func TestGet(t *testing.T) {
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

	uuid := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "get", "--format=json", "--uuid", uuid)

	// The output here should be in JSON with this structure:
	g := struct {
		Body           interface{}
		LogIndex       int
		IntegratedTime int64
	}{}
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

	uuid := getUUIDFromUploadOutput(t, out)

	out = runCli(t, "verify", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", pubPath, "--pki-format", "minisign")
	outputContains(t, out, "Inclusion Proof")

	out = runCli(t, "search", "--public-key", pubPath, "--pki-format", "minisign")
	outputContains(t, out, uuid)
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
			PredicateType: in_toto.PredicateProvenanceV01,
			Subject: []in_toto.Subject{
				{
					Name: "foobar",
					Digest: in_toto.DigestSet{
						"foo": "bar",
					},
				},
			},
		},
		Predicate: in_toto.ProvenancePredicate{
			Builder: in_toto.ProvenanceBuilder{
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
	signer, err := ssl.NewEnvelopeSigner(&IntotoSigner{
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

	// The atteestation should be stored at /var/run/attestations/$uuid
	cmd := exec.Command("docker", "run", "-v", "/var/run/attestations:/var/run/attestations", "alpine", "cat", "/var/run/attestations/"+uuid)
	b64, err := cmd.Output()
	if err != nil {
		t.Fatal(string(b64), err)
	}
	t.Logf("Read file contents: %s", string(b64))

	attStr, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		t.Fatal(err)
	}
	stored := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal([]byte(attStr), &stored); err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(it, stored); diff != "" {
		t.Errorf("diff: %s", diff)
	}

	out = runCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	outputContains(t, out, "Entry already exists")

}

func TestTimestampArtifact(t *testing.T) {
	payload := []byte("tell me when to go")
	filePath := filepath.Join(t.TempDir(), "file.txt")
	tsrPath := filepath.Join(t.TempDir(), "file.tsr")
	tsr2Path := filepath.Join(t.TempDir(), "file2.tsr")
	if err := ioutil.WriteFile(filePath, payload, 0644); err != nil {
		t.Fatal(err)
	}

	var out string
	out = runCli(t, "timestamp", "--artifact", filePath, "--out", tsrPath)
	outputContains(t, out, "Created entry at")
	uuid := getUUIDFromTimestampOutput(t, out)

	artifactBytes, err := ioutil.ReadFile(tsrPath)
	if err != nil {
		t.Error(err)
	}
	sha := sha256.Sum256(artifactBytes)

	out = runCli(t, "upload", "--type", "rfc3161", "--artifact", tsrPath)
	outputContains(t, out, "Entry already exists")

	out = runCli(t, "search", "--artifact", tsrPath)
	outputContains(t, out, uuid)

	out = runCli(t, "search", "--sha", fmt.Sprintf("sha256:%s", hex.EncodeToString(sha[:])))
	outputContains(t, out, uuid)

	// Generates a fresh timestamp on the same artifact
	out = runCli(t, "timestamp", "--artifact", filePath, "--out", tsr2Path)
	outputContains(t, out, "Created entry at")
}

func TestJARURL(t *testing.T) {
	out := runCli(t, "upload", "--artifact", "https://get.jenkins.io/war-stable/2.277.3/jenkins.war", "--type", "jar", "--artifact-hash=3e22c7e8cd7c8ee1e92cbaa8d0d303a7b53e07bc2a152ddc66f8ce55caea91ab")
	outputContains(t, out, "Created entry at")
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
	signature, _, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := s.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	// submit our newly signed payload to rekor
	rekorClient, err := client.GetRekorClient("http://localhost:3000")
	if err != nil {
		t.Fatal(err)
	}

	re := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(payload),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				Format:  models.RekordV001SchemaSignatureFormatX509,
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pemBytes),
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
	sig := logEntry.Verification.SignedEntryTimestamp
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

	// verify the signature against the public key
	h := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(rekorPubKey, h[:], []byte(sig)) {
		t.Fatal("unable to verify")
	}
}

func TestTimestampResponseCLI(t *testing.T) {
	ctx := context.Background()
	payload := []byte("i am a cat")
	// Create files for data, response, and CA.

	filePath := filepath.Join(t.TempDir(), "file.txt")
	CAPath := filepath.Join(t.TempDir(), "ca.pem")
	responsePath := filepath.Join(t.TempDir(), "response.tsr")
	if err := ioutil.WriteFile(filePath, payload, 0644); err != nil {
		t.Fatal(err)
	}

	out := runCli(t, "timestamp", "--artifact", filePath, "--out", responsePath)
	outputContains(t, out, "Wrote timestamp response to")

	rekorClient, err := client.GetRekorClient("http://localhost:3000")
	if err != nil {
		t.Fatal(err)
	}

	certChain := rekorTimestampCertChain(t, ctx, rekorClient)
	var rootCABytes bytes.Buffer
	if err := pem.Encode(&rootCABytes, &pem.Block{Type: "CERTIFICATE", Bytes: certChain[len(certChain)-1].Raw}); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(CAPath, rootCABytes.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// Use openssl to verify
	cmd := exec.Command("openssl", "ts", "-verify", "-data", filePath, "-in", responsePath, "-CAfile", CAPath)
	errs := &bytes.Buffer{}

	cmd.Stderr = errs
	if err := cmd.Run(); err != nil {
		// Check that the result was OK.
		if len(errs.Bytes()) > 0 {
			t.Fatalf("error verifying with openssl %s", errs.String())
		}

	}

	// Now try with the digest.
	h := sha256.Sum256(payload)
	hexDigest := hex.EncodeToString(h[:])
	out = runCli(t, "timestamp", "--artifact-hash", hexDigest, "--out", responsePath)
	outputContains(t, out, "Wrote timestamp response to")
	cmd = exec.Command("openssl", "ts", "-verify", "-digest", hexDigest, "-in", responsePath, "-CAfile", CAPath)
	errs = &bytes.Buffer{}

	cmd.Stderr = errs
	if err := cmd.Run(); err != nil {
		// Check that the result was OK.
		if len(errs.Bytes()) > 0 {
			t.Fatalf("error verifying with openssl %s", errs.String())
		}

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

func rekorTimestampCertChain(t *testing.T, ctx context.Context, c *genclient.Rekor) []*x509.Certificate {
	resp, err := c.Timestamp.GetTimestampCertChain(&timestamp.GetTimestampCertChainParams{Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	certChainBytes := []byte(resp.GetPayload())

	var block *pem.Block
	block, certChainBytes = pem.Decode(certChainBytes)
	certificates := []*x509.Certificate{}
	for ; block != nil; block, certChainBytes = pem.Decode(certChainBytes) {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			certificates = append(certificates, cert)
		} else {
			t.Fatal(err)
		}
	}

	if len(certificates) == 0 {
		t.Fatal("could not find certificates")
	}
	return certificates
}
