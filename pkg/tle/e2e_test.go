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
// +build e2e

package tle

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/util"
)

func TestAcceptTLE(t *testing.T) {
	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	sigPath := filepath.Join(td, "signature")
	certPath := filepath.Join(td, "cert.pem")
	pubKeyPath := filepath.Join(td, "key.pem")

	x509.CreatedX509SignedArtifact(t, artifactPath, sigPath)

	if err := os.WriteFile(certPath, []byte(x509.RSACert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubKeyPath, []byte(x509.PubKey), 0o644); err != nil {
		t.Fatal(err)
	}

	// upload so we have at least one entry in the log
	out := util.RunCli(t, "upload", "--artifact", artifactPath, "--signature", sigPath,
		"--public-key", certPath, "--pki-format", "x509")
	util.OutputContains(t, out, "Created entry at")

	// fetch via log UUID
	uuid, err := sharding.GetUUIDFromIDString(util.GetUUIDFromUploadOutput(t, out))
	if err != nil {
		t.Error(err)
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/log/entries/%s", util.RekorServer(), uuid), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Accept", TLEMediaType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if err := parseResponseAsTLE(t, resp); err != nil {
		t.Fatal(err)
	}

	// fetch via log index
	index := int64(util.GetLogIndexFromUploadOutput(t, out))

	req2, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", util.RekorServer(), index), nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Add("Accept", TLEMediaType)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if err := parseResponseAsTLE(t, resp2); err != nil {
		t.Fatal(err)
	}
	// fetch via search
	searchJSON := fmt.Sprintf("{ \"logIndexes\": [%d] }", index)
	req3, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/log/entries/retrieve", util.RekorServer()), strings.NewReader(searchJSON))
	if err != nil {
		t.Fatal(err)
	}
	req3.Header.Add("Accept", TLEMediaType)
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()

	if err := parseResponseAsTLEArray(t, resp3); err != nil {
		t.Fatal(err)
	}
}

func parseResponseAsTLE(t *testing.T, resp *http.Response) error {
	t.Helper()
	ctHeader := resp.Header.Get("Content-Type")
	if ctHeader != TLEMediaType {
		return fmt.Errorf("wrong Content-Type header received; expected '%s', got %s", TLEMediaType, ctHeader)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	msg := &rekor_pb.TransparencyLogEntry{}
	return protojson.Unmarshal(bodyBytes, msg)
}

func parseResponseAsTLEArray(t *testing.T, resp *http.Response) error {
	t.Helper()
	ctHeader := resp.Header.Get("Content-Type")
	if ctHeader != TLEMediaType {
		return fmt.Errorf("wrong Content-Type header received; expected '%s', got %s", TLEMediaType, ctHeader)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var jsonArray []json.RawMessage
	if err := json.Unmarshal(bodyBytes, &jsonArray); err != nil {
		return fmt.Errorf("expected array: %w", err)
	}

	for _, element := range jsonArray {
		msg := &rekor_pb.TransparencyLogEntry{}
		if err := protojson.Unmarshal(element, msg); err != nil {
			return fmt.Errorf("parsing element: %w", err)
		}
	}

	return nil
}
