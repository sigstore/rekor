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
	"bytes"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"

	"github.com/google/rpmpack"
)

func randomRpmSuffix() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, 16)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func createSignedRpm(t *testing.T, artifactPath string) {
	t.Helper()

	rpmMetadata := rpmpack.RPMMetaData{
		Name:    "test-rpm-" + randomRpmSuffix(),
		Epoch:   0,
		Version: "1",
		Release: "2",
		Arch:    "x86_64",
	}
	rpm, err := rpmpack.NewRPM(rpmMetadata)
	if err != nil {
		t.Error(err)
	}

	rpm.SetPGPSigner(SignPGP)

	data := randomData(t, 100)

	rpm.AddFile(rpmpack.RPMFile{
		Name:  randomRpmSuffix(),
		Body:  data,
		Type:  rpmpack.GenericFile,
		Owner: "testOwner",
		Group: "testGroup",
	})

	rpmBuf := bytes.Buffer{}
	if err := rpm.Write(&rpmBuf); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(artifactPath, rpmBuf.Bytes(), os.ModePerm); err != nil {
		t.Fatal(err)
	}
}
