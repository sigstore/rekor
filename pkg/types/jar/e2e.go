//
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

package jar

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"github.com/sigstore/rekor/pkg/util"
	"os"
	"strings"
	"testing"

	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/signjar"
	"github.com/sassoftware/relic/lib/zipslicer"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
)

//note: reuses PKI artifacts from x509 tests

const manifest = `Manifest-Version: 1.0
Created-By: REPLACE

Name: src/some/java/HelloWorld.class
SHA-256-Digest: cp40SgHlLIIr397GHijW7aAmWNLn0rgKm5Ap9B4hLd4=

`

// CreateSignedJar creates a signed JAR file with a single file inside
func CreateSignedJar(t *testing.T, artifactPath string) {
	t.Helper()

	//create a ZIP file with a single file inside
	f, err := os.Create(artifactPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	jw, err := zw.Create("src/some/java/HelloWorld.class")
	if err != nil {
		t.Fatal(err)
	}
	jw.Write([]byte("HelloWorld!"))
	mf, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	randManifest := strings.Replace(manifest, "REPLACE", util.RandomSuffix(16), 1)
	mf.Write([]byte(randManifest))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Sync()
	buf := bytes.Buffer{}
	zipslicer.ZipToTar(f, &buf)

	jd, err := signjar.DigestJarStream(&buf, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	c := certloader.Certificate{
		PrivateKey: sigx509.CertPrivateKey,
		Leaf:       sigx509.Certificate,
	}

	patch, _, err := jd.Sign(context.Background(), &c, "rekor", false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := patch.Apply(f, artifactPath); err != nil {
		t.Fatal(err)
	}
}
