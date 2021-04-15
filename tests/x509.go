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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

// Generated with:
// openssl ecparam -genkey -name prime256v1 > ec_private.pem
// openssl pkcs8 -topk8 -in ec_private.pem  -nocrypt
const ecdsaPriv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmrLtCpBdXgXLUr7o
nSUPfo3oXMjmvuwTOjpTulIBKlKhRANCAATH6KSpTFe6uXFmW1qNEFXaO7fWPfZt
pPZrHZ1cFykidZoURKoYXfkohJ+U/USYy8Sd8b4DMd5xDRZCnlDM0h37
-----END PRIVATE KEY-----`

// Extracted from above with:
// openssl ec -in ec_private.pem -pubout
const ecdsaPub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx+ikqUxXurlxZltajRBV2ju31j32
baT2ax2dXBcpInWaFESqGF35KISflP1EmMvEnfG+AzHecQ0WQp5QzNId+w==
-----END PUBLIC KEY-----`

// Generated with:
// openssl req -newkey rsa:2048 -nodes -keyout test.key -x509 -out test.crt
const rsaCert = `-----BEGIN CERTIFICATE-----
MIICujCCAaICCQDV0chJ/QVmCTANBgkqhkiG9w0BAQsFADAfMR0wGwYJKoZIhvcN
AQkBFg50ZXN0QHJla29yLmRldjAeFw0yMTAyMjAxOTUyMTZaFw0yMTAzMjIxOTUy
MTZaMB8xHTAbBgkqhkiG9w0BCQEWDnRlc3RAcmVrb3IuZGV2MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3wqI/TysUiKTgY1bz+wdJfEOil4MEsRASKGz
JddZ6x9hb+rn2UVoJmuxN62XI0TMoMn4mukgfCgY6jgTB58V+/LaeSA8Wz1p4gOx
hk1mcgbF4HyxR+xlRgYfH4iSbXy+Ez/8ZjM2OO68fKr4JZEA5LXZkhJr32JqH+Ui
Fw/wgSPWA8aV0AfRAXHdekJ48B1ChxJTrOJWSPTnj/E0lfLVsrJKtXDuC8T0vFmV
U726tI6fODsEE6VrSahvw1ENUHzI34sbfrmrggwPO4iMAQvqwu2gn2lx6ajWsh80
6FItiXN+DuizMnx4KMBI0IJynoQpWOFbstGiV0LygZkQ6sozvwIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQCe/lpUhsJVRkwXfndUEqiGVoPApGpwFMg4l1UnlPcbDXGV
+z564uZlS0LyjsJjaalP/CJ9R+DO5dpRcKmBzBbMHjGSqoFW/ZIUm8Yybnd2eC7b
JQD+JTB4XTd4yX3Yl6qWITPYpye3zuu3oCrHoBubWyzR9EakIaEBIenYReI4jD0n
40Erllt4ra2N0CkIaYei0ZfuMRkoav3jc+2OcbCzQzTDq7HIxfSirz9up6+hjn+G
GZXHemYIVbviNo9qr5cVY4OCJJQIUmGOcp+F4sNIqjbeEkTWFkeAy7sPSU8c8WQX
l7ArJO7hmz6eJON+xDbhcYtAOavUqbT+fVcgi2qm
-----END CERTIFICATE-----`

const rsaKey = `-----BEGIN PRIVATE KEY-----
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

// Extracted from the certificate using:
// openssl x509 -pubkey -noout -in test.crt
const pubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3wqI/TysUiKTgY1bz+wd
JfEOil4MEsRASKGzJddZ6x9hb+rn2UVoJmuxN62XI0TMoMn4mukgfCgY6jgTB58V
+/LaeSA8Wz1p4gOxhk1mcgbF4HyxR+xlRgYfH4iSbXy+Ez/8ZjM2OO68fKr4JZEA
5LXZkhJr32JqH+UiFw/wgSPWA8aV0AfRAXHdekJ48B1ChxJTrOJWSPTnj/E0lfLV
srJKtXDuC8T0vFmVU726tI6fODsEE6VrSahvw1ENUHzI34sbfrmrggwPO4iMAQvq
wu2gn2lx6ajWsh806FItiXN+DuizMnx4KMBI0IJynoQpWOFbstGiV0LygZkQ6soz
vwIDAQAB
-----END PUBLIC KEY-----`

var certPrivateKey *rsa.PrivateKey
var cert *x509.Certificate

func init() {
	p, _ := pem.Decode([]byte(rsaKey))
	priv, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	cpk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		panic("unsuccessful conversion")
	}
	certPrivateKey = cpk

	p, _ = pem.Decode([]byte(rsaCert))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		panic(err)
	}
}

func SignX509Cert(b []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(b)
	dgst := h.Sum(nil)
	signature, err := certPrivateKey.Sign(rand.Reader, dgst, crypto.SHA256)
	return signature, err
}

// createdX509SignedArtifact gets the test dir setup correctly with some random artifacts and keys.
func createdX509SignedArtifact(t *testing.T, artifactPath, sigPath string) {
	t.Helper()
	artifact := createArtifact(t, artifactPath)

	// Sign it with our key and write that to a file
	signature, err := SignX509Cert([]byte(artifact))
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(sigPath, []byte(signature), 0644); err != nil {
		t.Fatal(err)
	}
}
