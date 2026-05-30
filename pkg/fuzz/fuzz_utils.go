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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
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

// creates a temp file on disk and returns its url plus a cleanup func.
// Uses os.CreateTemp so parallel fuzz workers don't race on a fixed path in CWD.
func createAbsFile(_ *fuzz.ConsumeFuzzer, namePrefix string, fileContents []byte) (*url.URL, func(), error) {
	cleanup := func() {}
	file, err := os.CreateTemp("", namePrefix)
	if err != nil {
		return nil, cleanup, err
	}
	filePath := file.Name()
	cleanup = func() { os.Remove(filePath) }
	defer file.Close()

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, cleanup, err
	}
	fileURL, err := url.Parse(absPath)
	if err != nil {
		return nil, cleanup, err
	}
	if _, err := file.Write(fileContents); err != nil {
		return nil, cleanup, err
	}
	return fileURL, cleanup, nil
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
	signatureURL, sigCleanup, err := createAbsFile(ff, "SignatureFile", signatureBytes)
	if err != nil {
		sigCleanup()
		return cleanup, err
	}
	props.SignaturePath = signatureURL
	return sigCleanup, nil
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
	publicKeyURL, pkCleanup, err := createAbsFile(ff, "PublicKeyFile", publicKeyBytes)
	if err != nil {
		pkCleanup()
		return cleanup, err
	}
	props.PublicKeyPaths = []*url.URL{publicKeyURL}
	return pkCleanup, nil
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

// validPKIFormats mirrors pki.SupportedFormats(); duplicated here to avoid an
// import cycle and to keep the fuzzer's choice space small enough that the
// mutator can actually reach key-parsing code.
var validPKIFormats = []string{"pgp", "minisign", "ssh", "x509", "pkcs7", "tuf"}

// Sets the PKI format if the fuzzer decides to.
func setPKIFormat(ff *fuzz.ConsumeFuzzer, props *types.ArtifactProperties) error {
	shouldSetPKIFormat, err := ff.GetBool()
	if err != nil {
		return err
	}

	if shouldSetPKIFormat {
		idx, err := ff.GetInt()
		if err != nil {
			return err
		}
		props.PKIFormat = validPKIFormats[idx%len(validPKIFormats)]
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
			return files, errors.New("created an empty file")
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
		return *props, cleanups, errors.New("failed setting AdditionalAuthenticatedData")
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
		artifactFile, artifactCleanup, err := createAbsFile(ff, "ArtifactFile", artifactBytes)
		cleanups = append(cleanups, artifactCleanup)
		if err != nil {
			return *props, cleanups, fmt.Errorf("failed converting artifact bytes: %w", err)
		}
		props.ArtifactPath = artifactFile
	}

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

// AssertCanonicalIdempotent enforces the log-stability invariant: bytes
// produced by types.CanonicalizeEntry must, when re-parsed and
// re-canonicalized, yield the exact same bytes. A violation means the
// canonical form stored in the Merkle tree is not actually canonical.
func AssertCanonicalIdempotent(ctx context.Context, t *testing.T, canonical []byte) {
	t.Helper()
	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(canonical), runtime.JSONConsumer())
	if err != nil {
		t.Fatalf("canonical bytes failed to re-parse as ProposedEntry: %v\ncanonical: %s", err, canonical)
	}
	ei, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatalf("canonical bytes failed types.UnmarshalEntry: %v\ncanonical: %s", err, canonical)
	}
	canonical2, err := types.CanonicalizeEntry(ctx, ei)
	if err != nil {
		t.Fatalf("re-canonicalization of canonical bytes failed: %v\ncanonical: %s", err, canonical)
	}
	if !bytes.Equal(canonical, canonical2) {
		t.Fatalf("canonicalization not idempotent:\n first: %s\nsecond: %s", canonical, canonical2)
	}
}

// AssertDecodeEntryEquivalent feeds the same logical content to DecodeEntry
// once as a typed model and once as the map[string]any that encoding/json
// would produce, then asserts both code paths yield equivalent results. The
// per-type DecodeEntry functions hand-roll the map fast-path; divergence here
// means a field was forgotten or decoded differently.
func AssertDecodeEntryEquivalent[T any](t *testing.T, typed *T, decode func(any, *T) error) {
	t.Helper()
	raw, err := json.Marshal(typed)
	if err != nil {
		return
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return
	}

	var fromTyped, fromMap T
	errT := decode(typed, &fromTyped)
	errM := decode(asMap, &fromMap)
	if (errT == nil) != (errM == nil) {
		t.Fatalf("DecodeEntry error mismatch: typed=%v map=%v\ninput: %s", errT, errM, raw)
	}
	if errT != nil {
		return
	}
	// Restrict the byte-equality check to instances where both decode paths
	// produce schema-valid output. The hand-written map fast paths collapse
	// empty sub-objects to nil (which then fails Required validation),
	// whereas the typed path preserves the empty struct; reporting that for
	// every empty-field permutation across 11 types would drown out
	// meaningful field-level divergences.
	type validatable interface {
		Validate(strfmt.Registry) error
	}
	vt, okT := any(&fromTyped).(validatable)
	vm, okM := any(&fromMap).(validatable)
	if okT && okM {
		if vt.Validate(strfmt.Default) != nil || vm.Validate(strfmt.Default) != nil {
			return
		}
	}
	// Compare via JSON-semantic equality rather than byte equality:
	// encoding/json replaces invalid UTF-8 in Go strings with the \ufffd
	// escape on marshal, but emits the same code point as raw UTF-8 if it
	// was already valid, so a marshal/unmarshal round-trip on each side
	// normalises that before comparison.
	jt, _ := json.Marshal(fromTyped)
	jm, _ := json.Marshal(fromMap)
	var nt, nm any
	_ = json.Unmarshal(jt, &nt)
	_ = json.Unmarshal(jm, &nm)
	if !reflect.DeepEqual(nt, nm) {
		t.Fatalf("DecodeEntry divergence between typed and map paths:\ntyped: %s\n  map: %s\ninput: %s", jt, jm, raw)
	}
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
