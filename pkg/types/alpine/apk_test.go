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

package alpine

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/sigstore/rekor/pkg/pki/x509"
)

func TestAlpinePackage(t *testing.T) {
	inputArchive, err := os.Open("tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}
	defer inputArchive.Close()

	p := Package{}
	err = p.Unmarshal(inputArchive)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	pubKey, err := os.Open("tests/test_alpine.pub")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}
	defer pubKey.Close()

	pub, err := x509.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	if err = p.VerifySignature(pub.CryptoPubKey()); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestAlpineMetadataSize(t *testing.T) {
	origVal := viper.Get("max_apk_metadata_size")
	defer viper.Set("max_apk_metadata_size", origVal)

	viper.Set("max_apk_metadata_size", 10)

	inputArchive, err := os.Open("tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}
	defer inputArchive.Close()

	p := Package{}
	err = p.Unmarshal(inputArchive)
	if err == nil {
		t.Fatal("expecting metadata too large err")
	}
	if !strings.Contains(err.Error(), "exceeds max allowed size 10") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestAlpineMetadataSizeDefault(t *testing.T) {
	origVal := viper.Get("max_apk_metadata_size")
	defer viper.Set("max_apk_metadata_size", origVal)

	viper.Set("max_apk_metadata_size", 0)

	inputArchive, err := os.Open("tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}
	defer inputArchive.Close()

	p := Package{}
	err = p.Unmarshal(inputArchive)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
}

func TestAlpineMetadataSizeBoundary(t *testing.T) {
	origVal := viper.Get("max_apk_metadata_size")
	defer viper.Set("max_apk_metadata_size", origVal)

	// The signature.tar.gz decompressed size in test_alpine.apk is exactly 1024 bytes.
	boundary := 1024

	// 1. Verify that max_apk_metadata_size = 1024 succeeds
	viper.Set("max_apk_metadata_size", uint64(boundary))
	inputArchive, err := os.Open("tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}
	p := Package{}
	err = p.Unmarshal(inputArchive)
	inputArchive.Close()
	if err != nil {
		t.Fatalf("expected success at size %d, got err: %v", boundary, err)
	}

	// 2. Verify that max_apk_metadata_size = 1023 fails
	viper.Set("max_apk_metadata_size", uint64(boundary-1))
	inputArchive, err = os.Open("tests/test_alpine.apk")
	if err != nil {
		t.Fatalf("could not open archive %v", err)
	}
	defer inputArchive.Close()

	p = Package{}
	err = p.Unmarshal(inputArchive)
	if err == nil {
		t.Fatalf("expected failure at size %d", boundary-1)
	}

	// Decompressed size (1024) exceeds max allowed size (1023)
	expectedErr := fmt.Sprintf("decompressed size (%d) for signature.tar.gz exceeds max allowed size %d", boundary, boundary-1)
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error containing %q, got %q", expectedErr, err.Error())
	}
}
