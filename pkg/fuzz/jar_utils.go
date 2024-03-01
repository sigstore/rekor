//
// Copyright 2023 The Sigstore Authors.
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

package fuzz

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"

	"github.com/sassoftware/relic/lib/zipslicer"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/signjar"
)

var (
	CertPrivateKey *rsa.PrivateKey
	Certificate    *x509.Certificate
)

// copy pasted from rekor/pkg/pki/x509/e2e.go
const RSACert = `-----BEGIN CERTIFICATE-----
MIIDOjCCAiKgAwIBAgIUEP925shVBKERFCsymdSqESLZFyMwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGCSqGSIb3DQEJARYOdGVzdEByZWtvci5kZXYwHhcNMjEwNDIxMjAy
ODAzWhcNMjEwNTIxMjAyODAzWjAfMR0wGwYJKoZIhvcNAQkBFg50ZXN0QHJla29y
LmRldjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN8KiP08rFIik4GN
W8/sHSXxDopeDBLEQEihsyXXWesfYW/q59lFaCZrsTetlyNEzKDJ+JrpIHwoGOo4
EwefFfvy2nkgPFs9aeIDsYZNZnIGxeB8sUfsZUYGHx+Ikm18vhM//GYzNjjuvHyq
+CWRAOS12ZISa99iah/lIhcP8IEj1gPGldAH0QFx3XpCePAdQocSU6ziVkj054/x
NJXy1bKySrVw7gvE9LxZlVO9urSOnzg7BBOla0mob8NRDVB8yN+LG365q4IMDzuI
jAEL6sLtoJ9pcemo1rIfNOhSLYlzfg7oszJ8eCjASNCCcp6EKVjhW7LRoldC8oGZ
EOrKM78CAwEAAaNuMGwwHQYDVR0OBBYEFGjs8EHKT3x1itwwptJLuQQg/hQcMB8G
A1UdIwQYMBaAFGjs8EHKT3x1itwwptJLuQQg/hQcMA8GA1UdEwEB/wQFMAMBAf8w
GQYDVR0RBBIwEIEOdGVzdEByZWtvci5kZXYwDQYJKoZIhvcNAQELBQADggEBAAHE
bYuePN3XpM7pHoCz6g4uTHu0VrezqJyK1ohysgWJmSJzzazUeISXk0xWnHPk1Zxi
kzoEuysI8b0P7yodMA8e16zbIOL6QbGe3lNXYqRIg+bl+4OPFGVMX8xHNZmeh0kD
vX1JVS+y9uyo4/z/pm0JhaSCn85ft/Y5uXMQYn1wFR5DAcJH+iWjNX4fipGxGRE9
Cy0DjFnYJ3SRY4HPQ0oUSQmyhrwe2DiYzeqtbL2KJBXPcFQKWhkf/fupdYFljvcH
d9NNfRb0p2oFGG/J0ROg9pEcP1/aZP5k8P2pRdt3y7h1MAtmg2bgEdugZgXwAUmM
BmU8k2FeTuqV15piPCE=
-----END CERTIFICATE-----`

// copy pasted from rekor/pkg/pki/x509/e2e.go
const RSAKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfCoj9PKxSIpOB
jVvP7B0l8Q6KXgwSxEBIobMl11nrH2Fv6ufZRWgma7E3rZcjRMygyfia6SB8KBjq
OBMHnxX78tp5IDxbPWniA7GGTWZyBsXgfLFH7GVGBh8fiJJtfL4TP/xmMzY47rx8
qvglkQDktdmSEmvfYmof5SIXD/CBI9YDxpXQB9EBcd16QnjwHUKHElOs4lZI9OeP
8TSV8tWyskq1cO4LxPS8WZVTvbq0jp84OwQTpWtJqG/DUQ1QfMjfixt+uauCDA87
iIwBC+rC7aCfaXHpqNayHzToUi2Jc34O6LMyfHgowEjQgnKehClY4Vuy0aJXQvKB
mRDqyjO/AgMBAAECggEBAIHOAs3Gis8+WjRSjXVjh882DG1QsJwXZQYgPT+vpiAl
YjKdNpOHRkbd9ARgXY5kEuccxDd7p7E6MM3XFpQf7M51ltpZfWboRgAIgD+WOiHw
eSbdytr95C6tj11twTJBH+naGk1sTokxv7aaVdKfIjL49oeBexBFmVe4pW9gkmrE
1z1y1a0RohqbZ0kprYPWjz5UhsNqbCzgkdDqS7IrcOwVg6zvKYFjHnqIHqaJXVif
FgIfoNt7tz+12FTHI+6OkKoN3YCJueaxneBhITXm6RLOpQWa9qhdUPbkJ9vQNfph
Qqke4faaxKY9UDma+GpEHR016AWufZp92pd9wQkDn0kCgYEA7w/ZizAkefHoZhZ8
Isn/fYu4fdtUaVgrnGUVZobiGxWrHRU9ikbAwR7UwbgRSfppGiJdAMq1lyH2irmb
4OHU64rjuYSlIqUWHLQHWmqUbLUvlDojH/vdmH/Zn0AbrLZaimC5UCjK3Eb7sAMq
G0tGeDX2JraQvx7KrbC6peTaaaMCgYEA7tgZBiRCQJ7+mNu+gX9x6OXtjsDCh516
vToRLkxWc7LAbC9LKsuEHl4e3vy1PY/nyuv12Ng2dBq4WDXozAmVgz0ok7rRlIFp
w8Yj8o/9KuGZkD/7tw/pLsVc9Q3Wf0ACrnAAh7+3dAvn3yg+WHwXzqWIbrseDPt9
ILCfUoNDpzUCgYAKFCX8y0PObFd67lm/cbq2xUw66iNN6ay1BEH5t5gSwkAbksis
ar03pyAbJrJ75vXFZ0t6fBFZ1NG7GYYr3fmHEKz3JlN7+W/MN/7TXgjx6FWgLy9J
6ul1w3YeU6qXBn0ctmU5ru6WiNuVmRyOWAcZjFTbXvkNRbQPzJKh6dsXdwKBgA1D
FIihxMf/zBVCxl48bF/JPJqbm3GaTfFp4wBWHsrH1yVqrtrOeCSTh1VMZOfpMK60
0W7b+pIR1cCYJbgGpDWoVLN3QSHk2bGUM/TJB/60jilTVC/DA2ikbtfwj8N7E2sK
Lw1amN4ptxNOEcAqC8xepqe3XiDMahNBm2cigMQtAoGBAKwrXvss2BKz+/6poJQU
A0c7jhMN8M9Y5S2Ockw07lrQeAgfu4q+/8ztm0NeHJbk01IJvJY5Nt7bSgwgNVlo
j7vR2BMAc9U73Ju9aeTl/L6GqmZyA+Ojhl5gA5DPZYqNiqi93ydgRaI6n4+o3dI7
5wnr40AmbuKCDvMOvN7nMybL
-----END PRIVATE KEY-----`

// copy pasted from rekor/pkg/pki/x509/e2e.go
func init() {
	p, _ := pem.Decode([]byte(RSAKey))
	priv, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	cpk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		panic("unsuccessful conversion")
	}
	CertPrivateKey = cpk

	p, _ = pem.Decode([]byte(RSACert))
	Certificate, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		panic(err)
	}
}

// Creates jar artifact files.
func createJarArtifactFiles(ff *fuzz.ConsumeFuzzer) ([]*fuzz.TarFile, error) {
	var files []*fuzz.TarFile
	files, err := ff.TarFiles()
	if err != nil {
		return files, err
	}
	if len(files) <= 1 {
		return files, err
	}
	for _, file := range files {
		if len(file.Body) == 0 {
			return files, errors.New("Created an empty file")
		}
	}

	// add "META-INF/MANIFEST.MF"
	mfContents, err := ff.GetBytes()
	if err != nil {
		return files, err
	}

	// check the manifest early. This is an inexpensive check,
	// so we want to call it before compressing.
	_, err = signjar.ParseManifest(mfContents)
	if err != nil {
		return files, err
	}

	files = append(files, &fuzz.TarFile{
		Hdr: &tar.Header{
			Name:    "META-INF/MANIFEST.MF",
			Size:    int64(len(mfContents)),
			Mode:    0o600,
			ModTime: time.Unix(int64(123), int64(456)),
		},
		Body: mfContents,
	})
	return files, nil
}

func tarfilesToJar(artifactFiles []*fuzz.TarFile) ([]byte, error) {
	var jarBytes []byte
	f, err := os.Create("artifactFile")
	if err != nil {
		return jarBytes, err
	}
	defer f.Close()
	defer os.Remove("artifactFile")
	zw := zip.NewWriter(f)
	for _, zipFile := range artifactFiles {
		jw, err := zw.Create(zipFile.Hdr.Name)
		if err != nil {
			zw.Close()
			return jarBytes, err
		}
		_, err = jw.Write(zipFile.Body)
		if err != nil {
			continue
		}
	}
	zw.Close()
	err = f.Sync()
	if err != nil {
		return jarBytes, err
	}
	buf := bytes.Buffer{}
	err = zipslicer.ZipToTar(f, &buf)
	if err != nil {
		return jarBytes, err
	}

	jd, err := signjar.DigestJarStream(&buf, crypto.SHA256)
	if err != nil {
		os.Remove("artifactFile")
		return jarBytes, err
	}
	c := certloader.Certificate{
		PrivateKey: CertPrivateKey,
		Leaf:       Certificate,
	}

	patch, _, err := jd.Sign(context.Background(), &c, "rekor", false, true, false)
	if err != nil {
		return jarBytes, err
	}

	if err := patch.Apply(f, "artifactFile"); err != nil {
		return jarBytes, err
	}
	f.Close()

	artifactBytes, err := os.ReadFile("artifactFile")
	if err != nil {
		return jarBytes, err
	}
	return artifactBytes, nil
}
