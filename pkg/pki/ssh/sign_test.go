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

package ssh

import (
	"bytes"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	// Generated with "ssh-keygen -C test@rekor.dev -f id_rsa"
	sshPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`
	sshPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXofkiahE7uavjWvxnwkUF27qMgz7pdTwzSv0XzVG6EtirOv3PDWct4YKoXE9c0EqbxnIfYEKwEextdvB7zkgwczdJSHxf/18jQumLn/FuoCmugVSk1H5Qli/qzwBpaTnOk3WuakGuoYUl8ZAokKKgOKLA0aZJ1WRQ2ZCZggA3EkwNZiY17y9Q6HqdgQcH6XN8aAMADNVJdMAJb33hSRJjjsAPTmzBTishP8lYDoGRSsSE7/8XRBCEV5E4I8mI9GElcZwV/1KJx98mpH8QvMzXM1idFcwPRtt1NTAOshwgUU0Fu1x8lU5RQIa6ZKW36qNQLvLxy/BscC7B/mdLptoDs/ot9NimUXZcgCR1a2Q3o7Wi6jIgcgJcyV10Nba81ol4RdN4qPHnVZIzuo+dBkqwG3CMtB4Rj84+Qi+7zyU01hIPreoxQDXaayiGPBUUIiAlW9gsiuRWJzNnu3cvuWDLVfQIkjh7Wug58z+v2NOJ7IMdyERillhzDcvVHaq14+U= test@rekor.dev
`
	// Generated with "ssh-keygen -C other-test@rekor.dev -f id_rsa"
	otherSshPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`
	otherSshPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDD9YJJYL1MS8JA7A75PrwS81rc5Ii/VjT6xPy5K/KM/IQ7T6nS3wKD/PLru87GJClTmM3owi2NcCMyZ4KbwYoy3qCT5wOhoB6/9l+O7NIvtFrITGmaEGV6HZfcYouSRcX0AEU1yGVOpIs5mISMOg2lsW/XopPWwToKpbwOPFdCRCT0krrmEsf4HF5Yw0IQlVoKZrhfThomYLvMkCLnIZ55PRIpWoyiFq8X3Q7peJgUJAe7Bc8/Id+hyqC52ZeejPP7oPprEkpkzBCw2ndYq6Y6OXNafEEIIHWXaM3pFqDxonbbvuIwVdHCNMv/yNoSxbgqTKwN/QaNXb+KpuvSrlvRqsNhu/sKsYFH64fTAbP9miDXHmJkA05uFlQukOstUmJ0QxzbsdcFvs8yw0PLsEZhEHXJzR3TLzenyZSq86VZICvGfVacBk7TikCBOtyWuESHhlc6SfZKfzZ67cOlDyKeSiVjgh+eEh9s4h56ahQ2rW05Sq6GjD0YtEzog2J4csE= other-test@rekor.dev
`

	// Generated with ssh-keygen -C test@rekor.dev -t ed25519 -f id_ed25519
	ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBB45zRHxPPFtabwS3Vd6Lb9vMe+tIHZj2qN5VQ+bgLfQAAAJgyRa3cMkWt
3AAAAAtzc2gtZWQyNTUxOQAAACBB45zRHxPPFtabwS3Vd6Lb9vMe+tIHZj2qN5VQ+bgLfQ
AAAED7y4N/DsVnRQiBZNxEWdsJ9RmbranvtQ3X9jnb6gFed0HjnNEfE88W1pvBLdV3otv2
8x760gdmPao3lVD5uAt9AAAADnRlc3RAcmVrb3IuZGV2AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`
	ed25519PublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEHjnNEfE88W1pvBLdV3otv28x760gdmPao3lVD5uAt9 test@rekor.dev
`
)

func TestFromOpenSSH(t *testing.T) {
	for _, tt := range []struct {
		name string
		pub  string
		priv string
	}{
		{
			name: "rsa",
			pub:  sshPublicKey,
			priv: sshPrivateKey,
		},
		{
			name: "ed25519",
			pub:  ed25519PublicKey,
			priv: ed25519PrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt

			// Test that a signature from the cli can validate here.
			td := t.TempDir()

			data := []byte("hello, ssh world")
			dataPath := write(t, []byte(data), td, "data")

			privPath := write(t, []byte(tt.priv), td, "id")
			write(t, []byte(tt.pub), td, "id.pub")

			sigPath := dataPath + ".sig"
			run(t, nil, "ssh-keygen", "-Y", "sign", "-n", "file", "-f", privPath, dataPath)

			sigBytes, err := ioutil.ReadFile(sigPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(bytes.NewReader(data), sigBytes, []byte(tt.pub)); err != nil {
				t.Error(err)
			}

			// It should not verify if we check against another public key
			if err := Verify(bytes.NewReader(data), sigBytes, []byte(otherSshPublicKey)); err == nil {
				t.Error("expected error with incorrect key")
			}

			// It should not verify if the data is tampered
			if err := Verify(strings.NewReader("bad data"), sigBytes, []byte(sshPublicKey)); err == nil {
				t.Error("expected error with incorrect data")
			}
		})
	}
}

func TestToOpenSSH(t *testing.T) {
	for _, tt := range []struct {
		name string
		pub  string
		priv string
	}{
		{
			name: "rsa",
			pub:  sshPublicKey,
			priv: sshPrivateKey,
		},
		{
			name: "ed25519",
			pub:  ed25519PublicKey,
			priv: ed25519PrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			// Test that a signature from here can validate in the CLI.
			td := t.TempDir()

			data := []byte("hello, ssh world")
			write(t, []byte(data), td, "data")

			armored, err := Sign(tt.priv, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}

			sigPath := write(t, []byte(armored), td, "oursig")

			// Create an allowed_signers file with two keys to check against.
			allowedSigner := "test@rekor.dev " + tt.pub + "\n"
			allowedSigner += "othertest@rekor.dev " + otherSshPublicKey + "\n"
			allowedSigners := write(t, []byte(allowedSigner), td, "allowed_signer")

			// We use the correct principal here so it should work.
			run(t, data, "ssh-keygen", "-Y", "verify", "-f", allowedSigners,
				"-I", "test@rekor.dev", "-n", "file", "-s", sigPath)

			// Just to be sure, check against the other public key as well.
			runErr(t, data, "ssh-keygen", "-Y", "verify", "-f", allowedSigners,
				"-I", "othertest@rekor.dev", "-n", "file", "-s", sigPath)

			// It should error if we run it against other data
			data = []byte("other data!")
			runErr(t, data, "ssh-keygen", "-Y", "check-novalidate", "-n", "file", "-s", sigPath)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	data := []byte("my good data to be signed!")

	// Create one extra signature for all the tests.
	otherSig, err := Sign(otherSshPrivateKey, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		pub  string
		priv string
	}{
		{
			name: "rsa",
			pub:  sshPublicKey,
			priv: sshPrivateKey,
		},
		{
			name: "ed25519",
			pub:  ed25519PublicKey,
			priv: ed25519PrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			sig, err := Sign(tt.priv, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}

			// Check the signature against that data and public key
			if err := Verify(bytes.NewReader(data), sig, []byte(tt.pub)); err != nil {
				t.Error(err)
			}

			// Now check it against invalid data.
			if err := Verify(strings.NewReader("invalid data!"), sig, []byte(tt.pub)); err == nil {
				t.Error("expected error!")
			}

			// Now check it against the wrong key.
			if err := Verify(bytes.NewReader(data), sig, []byte(otherSshPublicKey)); err == nil {
				t.Error("expected error!")
			}

			// Now check it against an invalid signature data.
			if err := Verify(bytes.NewReader(data), []byte("invalid signature!"), []byte(tt.pub)); err == nil {
				t.Error("expected error!")
			}

			// Once more, use the wrong signature and check it against the original (wrong public key)
			if err := Verify(bytes.NewReader(data), otherSig, []byte(tt.pub)); err == nil {
				t.Error("expected error!")
			}
			// It should work against the correct public key.
			if err := Verify(bytes.NewReader(data), otherSig, []byte(otherSshPublicKey)); err != nil {
				t.Error(err)
			}
		})
	}

}

func write(t *testing.T, d []byte, fp ...string) string {
	p := filepath.Join(fp...)
	if err := ioutil.WriteFile(p, d, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, stdin []byte, args ...string) {
	t.Helper()
	/* #nosec */
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	t.Logf("cmd %v: %s", cmd, string(out))
	if err != nil {
		t.Fatal(err)
	}
}

func runErr(t *testing.T, stdin []byte, args ...string) {
	t.Helper()
	/* #nosec */
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	t.Logf("cmd %v: %s", cmd, string(out))
	if err == nil {
		t.Fatal("expected error")
	}
}
