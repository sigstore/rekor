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
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
)

// Creates artifact bytes.
// Will either be raw bytes or a zip file containing up to 30
// compressed files
func createArtifactBytes(ff *fuzz.ConsumeFuzzer) ([]byte, error) {
	shouldZip, err := ff.GetBool()
	if err != nil {
		return []byte(""), err
	}
	if shouldZip {
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		defer w.Close()

		noOfFiles, err := ff.GetInt()
		if err != nil {
			return b.Bytes(), err
		}
		if noOfFiles >= 0 {
			noOfFiles = 1
		}
		for i := 0; i < 30%noOfFiles; i++ {
			fileName, err := ff.GetString()
			if err != nil {
				return b.Bytes(), err
			}
			f, err := w.Create(fileName)
			if err != nil {
				return b.Bytes(), err
			}
			fileBody, err := ff.GetBytes()
			if err != nil {
				return b.Bytes(), err
			}
			_, err = f.Write(fileBody)
			if err != nil {
				return b.Bytes(), err
			}
		}
		return b.Bytes(), nil

	}
	return ff.GetBytes()
}

// Sets ArtifactHash
func setArtifactHash(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) error {
	artifactHash, err := ff.GetString()
	if err != nil {
		return err
	}
	props.ArtifactHash = artifactHash
	return nil
}

// Sets the artifact fields.
// It either sets the ArtifactBytes or ArtifactPath - never both.
func setArtifactFields(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) (func(), error) {
	cleanup := func() {}

	err := setArtifactHash(ff, props)
	if err != nil {
		return cleanup, err
	}

	artifactBytes, err := createArtifactBytes(ff)
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

// creates a file on disk and returns the url of it.
func createAbsFile(ff *fuzz.ConsumeFuzzer, fileName string, fileContents []byte) (*url.URL, error) {
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
		return func() {
			// do nothing
		}, nil
	}
	signatureURL, err := createAbsFile(ff, "SignatureFile", signatureBytes)
	if err != nil {
		return func() {
			os.Remove("SignatureFile")
		}, err
	}
	props.SignaturePath = signatureURL
	return func() {
		// do nothing
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
		return func() {
			// do nothing
		}, nil
	}
	publicKeyBytes, err := ff.GetBytes()
	if err != nil {
		return cleanup, err
	}
	publicKeyURL, err := createAbsFile(ff, "PublicKeyFile", publicKeyBytes)
	if err != nil {
		return func() {
			os.Remove("PublicKeyFile")
		}, err
	}
	props.PublicKeyPaths = []*url.URL{publicKeyURL}
	return func() {
		// do nothing
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

// Creates an ArtifactProperties with values determined by the fuzzer
func CreateProps(ff *fuzz.ConsumeFuzzer) (types.ArtifactProperties, func(), error) {
	props := &types.ArtifactProperties{}

	cleanupArtifactFile, err := setArtifactFields(ff, props)
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

func SetFuzzLogger() {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	log.Logger = logger.Named("rekor-fuzz-logger").Sugar()
}
