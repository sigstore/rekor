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
	"fmt"
	"github.com/sassoftware/relic/lib/zipslicer"
	"github.com/sassoftware/relic/v7/lib/certloader"
	"github.com/sassoftware/relic/v7/lib/signjar"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"os"
	"time"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
)

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
			return files, fmt.Errorf("Created an empty file")
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
		jw.Write(zipFile.Body)
	}
	zw.Close()
	f.Sync()
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
		PrivateKey: sigx509.CertPrivateKey,
		Leaf:       sigx509.Certificate,
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
