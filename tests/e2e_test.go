// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func getUUIDFromUploadOutput(t *testing.T, out string) string {
	t.Helper()
	// Output looks like "Created entry at index X, available at $URL/UUID", so grab the UUID:
	urlTokens := strings.Split(strings.TrimSpace(out), " ")
	url := urlTokens[len(urlTokens)-1]
	splitUrl := strings.Split(url, "/")
	return splitUrl[len(splitUrl)-1]
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
		if err != nil {
			t.Fatal(err)
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
