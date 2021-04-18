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
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"os"
	"testing"

	"github.com/sassoftware/relic/lib/certloader"
	"github.com/sassoftware/relic/lib/signjar"
	"github.com/sassoftware/relic/lib/zipslicer"
)

//note: reuses PKI artifacts from x509 tests

const manifest = `Manifest-Version: 1.0

Name: src/some/java/HelloWorld.class
SHA-256-Digest: cp40SgHlLIIr397GHijW7aAmWNLn0rgKm5Ap9B4hLd4=

`

func createSignedJar(t *testing.T, artifactPath string) {
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
	mf.Write([]byte(manifest))
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
		PrivateKey: certPrivateKey,
		Leaf:       cert,
	}

	patch, _, err := jd.Sign(context.Background(), &c, "rekor", false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := patch.Apply(f, artifactPath); err != nil {
		t.Fatal(err)
	}
}
