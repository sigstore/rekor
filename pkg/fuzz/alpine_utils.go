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
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/sigstore/rekor/pkg/types"
)

// Allows the fuzzer to create a .SIGN filename
func getSignFilename(ff *fuzz.ConsumeFuzzer) (string, error) {
	keyName, err := ff.GetString()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(".SIGN.RSA.")
	b.WriteString(keyName)
	b.WriteString(".rsa.pub")
	return b.String(), nil
}

// createPkgInfoFileContents creates a structured pkginfo file
//
// .PKGINFO files look like this:
//
// # Generated by abuild 3.9.0-r2
// # using fakeroot version 1.25.3
// # Wed Jul  6 19:09:49 UTC 2022
// pkgname = busybox
// pkgver = 1.35.0-r18
// pkgdesc = Size optimized toolbox of many common UNIX utilities
// url = https://busybox.net/
// builddate = 1657134589
// packager = Buildozer <developer@email.org>
// size = 958464
// arch = x86_64
// origin = busybox
// commit = 332d2fff53cd4537d415e15e55e8ceb6fe6eaedb
// maintainer = Sören Tempel <soeren+alpine@soeren-tempel.net>
// provider_priority = 100
// license = GPL-2.0-only
// replaces = busybox-initscripts
// provides = /bin/sh
// triggers = /bin /usr/bin /sbin /usr/sbin /lib/modules/*
// # automatically detected:
// provides = cmd:busybox=1.35.0-r18
// provides = cmd:sh=1.35.0-r18
// depend = so:libc.musl-x86_64.so.1
// datahash = 7d3351ac6c3ebaf18182efb5390061f50d077ce5ade60a15909d91278f70ada7
func createPkgInfoFileContents(ff *fuzz.ConsumeFuzzer) ([]byte, error) {
	var b strings.Builder
	noOfRows, err := ff.GetInt()
	if err != nil {
		return []byte(""), err
	}

	// Comments at the top of the pkginfo file
	header, err := ff.GetBytes()
	if err != nil {
		return []byte(""), err
	}
	b.Write(header)

	for i := 0; i < noOfRows; i++ {
		key, err := ff.GetBytes()
		if err != nil {
			return []byte(""), err
		}
		value, err := ff.GetBytes()
		if err != nil {
			return []byte(""), err
		}
		b.Write(key)
		b.Write([]byte(" = "))
		b.Write(value)
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// Adds a .SIGN file to tarBytes
func addSignFile(ff *fuzz.ConsumeFuzzer, tarFiles []*fuzz.TarFile) ([]*fuzz.TarFile, error) {
	SIGNFileContents, err := ff.GetBytes()
	if err != nil {
		return tarFiles, err
	}

	SIGNFileName, err := getSignFilename(ff)
	if err != nil {
		return tarFiles, err
	}
	signFile := &fuzz.TarFile{
		Body: SIGNFileContents,
		Hdr: &tar.Header{
			Name:     SIGNFileName,
			Mode:     0644,
			Size:     int64(len(SIGNFileContents)),
			Typeflag: tar.TypeReg,
			Gid:      0,
			Uid:      0,
		},
	}
	tarFiles = append(tarFiles, signFile)

	return tarFiles, nil
}

// Allows the fuzzer to randomize whether a .SIGN file should
// be added to tarBytes
func shouldAddSignFile(ff *fuzz.ConsumeFuzzer, tarFiles []*fuzz.TarFile) bool {
	shouldRequireSIGNFile, err := ff.GetBool()
	if err != nil {
		return false
	}
	if shouldRequireSIGNFile {
		for _, tarFile := range tarFiles {
			if strings.HasPrefix(tarFile.Hdr.Name, ".SIGN") {
				return false
			}
		}
		return true
	}
	return false
}

// Allows the fuzzer to randomize whether a .PKGINFO file should
// be added to tarBytes
func shouldAddPkgInfoFile(ff *fuzz.ConsumeFuzzer, tarFiles []*fuzz.TarFile) bool {
	shouldRequirePKGINFOFile, err := ff.GetBool()
	if err != nil {
		return false
	}
	if shouldRequirePKGINFOFile {
		for _, tarFile := range tarFiles {
			if strings.HasPrefix(tarFile.Hdr.Name, ".PKGINFO") {
				return false
			}
		}
		return true
	}
	return false
}

// Adds the .PKGINFO file to the tar files
func addPkgInfoFile(ff *fuzz.ConsumeFuzzer, tarFiles []*fuzz.TarFile) ([]*fuzz.TarFile, error) {
	tarFile := &fuzz.TarFile{}
	PKGINFOFileContents, err := createPkgInfoFileContents(ff)
	if err != nil {
		return tarFiles, err
	}
	tarFile.Body = PKGINFOFileContents
	tarFile.Hdr = &tar.Header{
		Name:     ".PKGINFO",
		Mode:     0644,
		Size:     int64(len(PKGINFOFileContents)),
		Typeflag: tar.TypeReg,
		Gid:      0,
		Uid:      0,
	}

	return tarFiles, nil
}

func AlpineArtifactBytes(ff *fuzz.ConsumeFuzzer) ([]byte, error) {
	var tarFiles, tarFiles2 []*fuzz.TarFile
	var err error

	tarFiles, err = ff.TarFiles()
	if err != nil {
		return []byte(""), err
	}
	if shouldAddSignFile(ff, tarFiles) {
		tarFiles, err = addSignFile(ff, tarFiles)
		if err != nil {
			return []byte(""), err
		}
	}

	tarFiles2, err = ff.TarFiles()
	if err != nil {
		return []byte(""), err
	}

	if shouldAddPkgInfoFile(ff, tarFiles2) {
		tarFiles2, err = addPkgInfoFile(ff, tarFiles2)
		if err != nil {
			return []byte(""), err
		}
	}

	return concatenateTarArchives(tarFiles, tarFiles2)
}

func concatenateTarArchives(tarFiles1 []*fuzz.TarFile, tarFiles2 []*fuzz.TarFile) ([]byte, error) {
	var buf1, buf2 bytes.Buffer
	var err error

	tw1 := tar.NewWriter(&buf1)
	for _, tf := range tarFiles1 {
		err = tw1.WriteHeader(tf.Hdr)
		if err != nil {
			return []byte(""), err
		}
		_, err = tw1.Write(tf.Body)
		if err != nil {
			return []byte(""), err
		}
	}
	tw1.Close()
	tarBytes := buf1.Bytes()

	tw2 := tar.NewWriter(&buf2)
	for _, tf := range tarFiles2 {
		err = tw2.WriteHeader(tf.Hdr)
		if err != nil {
			return []byte(""), err
		}
		_, err = tw2.Write(tf.Body)
		if err != nil {
			return []byte(""), err
		}
	}
	tw2.Close()
	tarBytes2 := buf2.Bytes()

	var b1 bytes.Buffer
	w1 := gzip.NewWriter(&b1)
	defer w1.Close()
	_, err = w1.Write(tarBytes)
	if err != nil {
		return []byte(""), err
	}
	w1.Close()

	var b2 bytes.Buffer
	w2 := gzip.NewWriter(&b2)
	defer w2.Close()
	_, err = w2.Write(tarBytes2)
	if err != nil {
		return []byte(""), err
	}
	w2.Close()
	concatenated := append(b1.Bytes(), b2.Bytes()...)
	return concatenated, nil
}

func setAlpineArtifactFields(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) (func(), error) {
	cleanup := func() {}

	err := setArtifactHash(ff, props)
	if err != nil {
		return cleanup, err
	}

	artifactBytes, err := AlpineArtifactBytes(ff)
	if err != nil {
		return cleanup, err
	}

	shouldSetArtifactBytes, err := ff.GetBool()
	if err != nil {
		return cleanup, err
	}

	if shouldSetArtifactBytes {
		props.ArtifactBytes = artifactBytes
		return func() {
			// do nothing
		}, nil
	}
	artifactFile, err := createAbsFile(ff, "ArtifactFile", artifactBytes)
	cleanup = func() {
		os.Remove("ArtifactFile")
	}
	props.ArtifactPath = artifactFile
	return cleanup, err
}

// Creates an ArtifactProperties with values determined by the fuzzer
func CreateAlpineProps(ff *fuzz.ConsumeFuzzer) (types.ArtifactProperties, func(), error) {
	props := &types.ArtifactProperties{}

	cleanupArtifactFile, err := setAlpineArtifactFields(ff, props)
	if err != nil {
		return *props, cleanupArtifactFile, err
	}
	if props.ArtifactPath == nil && props.ArtifactBytes == nil {
		return *props, cleanupArtifactFile, fmt.Errorf("ArtifactPath and ArtifactBytes cannot both be nil")
	}

	err = setAdditionalAuthenticatedData(ff, props)
	if err != nil {
		return *props, cleanupArtifactFile, fmt.Errorf("Failed setting AdditionalAuthenticatedData")
	}

	cleanupSignatureFile, err := setSignatureFields(ff, props)
	if err != nil {
		return *props, func() {
			cleanupArtifactFile()
			cleanupSignatureFile()
		}, fmt.Errorf("failed setting signature fields: %v", err)
	}

	cleanupPublicKeyFile, err := setPublicKeyFields(ff, props)
	if err != nil {
		return *props, func() {
			cleanupArtifactFile()
			cleanupSignatureFile()
			cleanupPublicKeyFile()
		}, fmt.Errorf("failed setting public key fields: %v", err)
	}

	err = setPKIFormat(ff, props)
	if err != nil {
		return *props, func() {
			cleanupArtifactFile()
			cleanupSignatureFile()
			cleanupPublicKeyFile()
		}, fmt.Errorf("failed setting PKI Format: %v", err)
	}

	return *props, func() {
		cleanupArtifactFile()
		cleanupSignatureFile()
		cleanupPublicKeyFile()
	}, nil
}
