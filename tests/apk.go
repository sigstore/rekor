// +build e2e

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

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

func createSignedApk(t *testing.T, artifactPath string) {
	t.Helper()

	data := randomData(t, 100)
	dataTarBuf := bytes.Buffer{}
	dataTar := tar.NewWriter(&dataTarBuf)
	dataTar.WriteHeader(&tar.Header{Name: "random.txt", Size: int64(len(data))})
	dataTar.Write(data)
	dataTar.Close()

	dataTGZBuf := bytes.Buffer{}
	dataGZ, _ := gzip.NewWriterLevel(&dataTGZBuf, gzip.BestCompression)
	dataGZ.Write(dataTarBuf.Bytes())
	dataGZ.Close()

	datahash := sha256.Sum256(dataTGZBuf.Bytes())

	ctlData := strings.Builder{}
	ctlData.WriteString("name = " + randomRpmSuffix())
	ctlData.WriteRune('\n')
	ctlData.WriteString("datahash = " + hex.EncodeToString(datahash[:]))
	ctlData.WriteRune('\n')
	ctlTarBuf := bytes.Buffer{}
	ctlTar := tar.NewWriter(&ctlTarBuf)
	ctlTar.WriteHeader(&tar.Header{Name: ".PKGINFO", Size: int64(ctlData.Len())})
	ctlTar.Write([]byte(ctlData.String()))
	ctlTar.Flush()
	// do not close so uncompressed stream appears as contiguous tar archive

	ctlTGZBuf := bytes.Buffer{}
	ctlGZ, _ := gzip.NewWriterLevel(&ctlTGZBuf, gzip.BestCompression)
	ctlGZ.Write(ctlTarBuf.Bytes())
	ctlGZ.Close()

	sha1sum := sha1.Sum(ctlTGZBuf.Bytes())
	sig, _ := rsa.SignPKCS1v15(crand.Reader, certPrivateKey, crypto.SHA1, sha1sum[:])

	sigTarBuf := bytes.Buffer{}
	sigTar := tar.NewWriter(&sigTarBuf)
	sigTar.WriteHeader(&tar.Header{Name: ".SIGN.RSA.fixed.pub", Size: int64(len(sig))})
	sigTar.Write(sig)
	sigTar.Flush()
	// do not close so uncompressed stream appears as contiguous tar archive

	sigTGZBuf := bytes.Buffer{}
	sigGZ, _ := gzip.NewWriterLevel(&sigTGZBuf, gzip.BestCompression)
	sigGZ.Write(sigTarBuf.Bytes())
	sigGZ.Close()

	apkBuf := bytes.Buffer{}
	if _, err := io.Copy(&apkBuf, io.MultiReader(&sigTGZBuf, &ctlTGZBuf, &dataTGZBuf)); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(artifactPath, apkBuf.Bytes(), 777); err != nil {
		t.Fatal(err)
	}
}
