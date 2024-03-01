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

package fuzz

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
)

// Sets ArtifactHash
func setArtifactHash(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) error {
	artifactHash, err := ff.GetString()
	if err != nil {
		return err
	}
	props.ArtifactHash = artifactHash
	return nil
}

// creates a file on disk and returns the url of it.
func createAbsFile(_ *fuzz.ConsumeFuzzer, fileName string, fileContents []byte) (*url.URL, error) {
	file, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filePath, err := filepath.Abs(fileName)
	if err != nil {
		return nil, err
	}
	fileURL, err := url.Parse(filePath)
	if err != nil {
		return nil, err
	}
	_, err = file.Write(fileContents)
	if err != nil {
		return nil, err
	}
	return fileURL, err
}

// Sets the signature fields of a props.
// It either sets SignatureBytes or SignaturePath
func setSignatureFields(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) (func(), error) {
	cleanup := func() {}
	shouldSetSignatureBytes, err := ff.GetBool()
	if err != nil {
		return cleanup, err
	}

	signatureBytes, err := ff.GetBytes()
	if err != nil {
		return cleanup, err
	}

	if shouldSetSignatureBytes {
		props.SignatureBytes = signatureBytes
		return cleanup, nil
	}
	signatureURL, err := createAbsFile(ff, "SignatureFile", signatureBytes)

	if err != nil {
		os.Remove("SignatureFile")
		return cleanup, err
	}
	props.SignaturePath = signatureURL
	return func() {
		os.Remove("SignatureFile")
	}, nil

}

func setPublicKeyFields(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) (func(), error) {
	cleanup := func() {}

	shouldSetPublicKeyBytes, err := ff.GetBool()
	if err != nil {
		return cleanup, err
	}

	if shouldSetPublicKeyBytes {
		publicKeyBytes := make([][]byte, 0)
		err := ff.GenerateStruct(&publicKeyBytes)
		if err != nil || len(publicKeyBytes) == 0 {
			return cleanup, err
		}
		props.PublicKeyBytes = publicKeyBytes
		return cleanup, nil
	}
	publicKeyBytes, err := ff.GetBytes()
	if err != nil {
		return cleanup, err
	}
	publicKeyURL, err := createAbsFile(ff, "PublicKeyFile", publicKeyBytes)
	if err != nil {
		os.Remove("PublicKeyFile")
		return cleanup, err
	}
	props.PublicKeyPaths = []*url.URL{publicKeyURL}
	return func() {
		os.Remove("PublicKeyFile")
	}, nil
}

// Sets the "AdditionalAuthenticatedData" field of the props
func setAdditionalAuthenticatedData(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) error {
	shouldSetAdditionalAuthenticatedData, err := ff.GetBool()
	if err != nil {
		return err
	}
	if shouldSetAdditionalAuthenticatedData {
		additionalAuthenticatedData, err := ff.GetBytes()
		if err != nil {
			return err
		}
		props.AdditionalAuthenticatedData = additionalAuthenticatedData
	}
	return nil
}

// Sets the PKI format if the fuzzer decides to.
func setPKIFormat(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) error {
	shouldSetPKIFormat, err := ff.GetBool()
	if err != nil {
		return err
	}

	if shouldSetPKIFormat {
		pkiFormat, err := ff.GetString()
		if err != nil {
			return err
		}
		props.PKIFormat = pkiFormat
	}

	return nil
}

func createArtifactFiles(ff *fuzz.ConsumeFuzzer, artifactType string) ([]*fuzz.TarFile, error) {
	switch artifactType {
	case "jarV001":
		return createJarArtifactFiles(ff)
	default:
		return createDefaultArtifactFiles(ff)
	}
}

func createDefaultArtifactFiles(ff *fuzz.ConsumeFuzzer) ([]*fuzz.TarFile, error) {
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
	return files, nil
}

// Creates an ArtifactProperties with values determined by the fuzzer
func CreateProps(ff *fuzz.ConsumeFuzzer, fuzzType string) (types.ArtifactProperties, []func(), error) {
	var cleanups []func()

	props := &types.ArtifactProperties{}

	err := setArtifactHash(ff, props)
	if err != nil {
		return *props, cleanups, err
	}

	artifactFiles, err := createArtifactFiles(ff, fuzzType)
	if err != nil {
		return *props, cleanups, err
	}

	err = setAdditionalAuthenticatedData(ff, props)
	if err != nil {
		return *props, cleanups, errors.New("Failed setting AdditionalAuthenticatedData")
	}

	cleanupSignatureFile, err := setSignatureFields(ff, props)
	if err != nil {
		return *props, cleanups, fmt.Errorf("failed setting signature fields: %w", err)
	}
	cleanups = append(cleanups, cleanupSignatureFile)

	cleanupPublicKeyFile, err := setPublicKeyFields(ff, props)
	if err != nil {
		return *props, cleanups, fmt.Errorf("failed setting public key fields: %w", err)
	}
	cleanups = append(cleanups, cleanupPublicKeyFile)

	err = setPKIFormat(ff, props)
	if err != nil {
		return *props, cleanups, fmt.Errorf("failed setting PKI Format: %w", err)
	}

	artifactBytes, err := tarFilesToBytes(artifactFiles, fuzzType)
	if err != nil {
		return *props, cleanups, fmt.Errorf("failed converting artifact bytes: %w", err)
	}

	setArtifactBytes, err := ff.GetBool()
	if err != nil {
		return *props, cleanups, fmt.Errorf("failed converting artifact bytes: %w", err)
	}
	if setArtifactBytes {
		props.ArtifactBytes = artifactBytes
	} else {
		artifactFile, err := createAbsFile(ff, "ArtifactFile", artifactBytes)
		cleanups = append(cleanups, func() { os.Remove("ArtifactFile") })
		if err != nil {
			return *props, cleanups, fmt.Errorf("failed converting artifact bytes: %w", err)
		}
		props.ArtifactPath = artifactFile
	}

	props.ArtifactBytes = artifactBytes
	return *props, cleanups, nil
}

func tarFilesToBytes(artifactFiles []*fuzz.TarFile, artifactType string) ([]byte, error) {
	switch artifactType {
	case "jarV001":
		return tarfilesToJar(artifactFiles)
	default:
		return defaultTarToBytes(artifactFiles)
	}
}

func defaultTarToBytes(artifactFiles []*fuzz.TarFile) ([]byte, error) {
	b := new(bytes.Buffer)
	w := zip.NewWriter(b)

	for _, file := range artifactFiles {
		f, err := w.Create(file.Hdr.Name)
		if err != nil {
			continue
		}
		_, _ = f.Write(file.Body)
	}

	w.Close()
	return b.Bytes(), nil
}

func SetFuzzLogger() {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	log.Logger = logger.Named("rekor-fuzz-logger").Sugar()
}
