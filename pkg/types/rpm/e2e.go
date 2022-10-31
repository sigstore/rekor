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

package rpm

import (
	"bytes"
	"github.com/sigstore/rekor/pkg/util"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/rpmpack"
)

func CreateSignedRpm(t *testing.T, artifactPath string) {
	t.Helper()

	rpmMetadata := rpmpack.RPMMetaData{
		Name:    "test-rpm-" + util.RandomSuffix(16),
		Epoch:   0,
		Version: "1",
		Release: "2",
		Arch:    "x86_64",
	}
	rpm, err := rpmpack.NewRPM(rpmMetadata)
	if err != nil {
		t.Error(err)
	}

	rpm.SetPGPSigner(util.SignPGP)

	data := util.RandomData(t, 100)

	rpm.AddFile(rpmpack.RPMFile{
		Name:  util.RandomSuffix(16),
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
