/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
)

/*
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
*/

func TestArtifactPFlags(t *testing.T) {
	type test struct {
		caseDesc      string
		rekord        string
		artifact      string
		signature     string
		publicKey     string
		sha           string
		expectSuccess bool
	}

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file, err := ioutil.ReadFile("../../../tests/test_file.txt")
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	tests := []test{
		{
			caseDesc:      "valid rekord file",
			rekord:        "../../../tests/rekor.json",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existant rekord file",
			rekord:        "../../../tests/not_there.json",
			expectSuccess: false,
		},
		{
			caseDesc:      "no flags",
			expectSuccess: false,
		},
		{
			caseDesc:      "valid local artifact with required flags",
			artifact:      "../../../tests/test_file.txt",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: true,
		},
		{
			caseDesc:      "valid local artifact with incorrect length hex SHA value",
			artifact:      "../../../tests/test_file.txt",
			sha:           "12345abcde",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
		{
			caseDesc:      "nonexistant local artifact",
			artifact:      "../../../tests/not_a_file",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
		{
			caseDesc:      "local artifact without required signature",
			artifact:      "../../../tests/test_file.txt",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
		{
			caseDesc:      "local artifact with invalid signature",
			artifact:      "../../../tests/test_file.txt",
			signature:     "../../../tests/not_a_file",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
		{
			caseDesc:      "local artifact without required public key",
			artifact:      "../../../tests/test_file.txt",
			signature:     "../../../tests/test_file.sig",
			expectSuccess: false,
		},
		{
			caseDesc:      "local artifact with invalid public key",
			artifact:      "../../../tests/test_file.txt",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/not_a_file",
			expectSuccess: false,
		},
		{
			caseDesc:      "valid remote artifact with required flags",
			artifact:      testServer.URL,
			sha:           "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: true,
		},
		{
			caseDesc:      "remote artifact with invalid URL",
			artifact:      "hteeteep%**/test_file.txt",
			sha:           "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
		{
			caseDesc:      "remote artifact without required sha",
			artifact:      testServer.URL,
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
		{
			caseDesc:      "remote artifact with invalid sha",
			artifact:      testServer.URL,
			sha:           "1345not%hash%",
			signature:     "../../../tests/test_file.sig",
			publicKey:     "../../../tests/test_public_key.key",
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		viper.Reset()
		viper.Set("rekord", tc.rekord)
		viper.Set("artifact", tc.artifact)
		viper.Set("signature", tc.signature)
		viper.Set("public-key", tc.publicKey)
		viper.Set("sha", tc.sha)
		if err := validateArtifactPFlags(); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		if tc.expectSuccess {
			if _, err := buildRekorEntryFromPFlags(); err != nil {
				t.Errorf("unexpected result in '%v' building Rekor Entry: %v", tc.caseDesc, err)
			}
		}
	}
}

func TestValidateRekorServerURL(t *testing.T) {
	type test struct {
		caseDesc      string
		rekorServer   string
		expectSuccess bool
	}

	tests := []test{
		{
			caseDesc:      "value not specified",
			expectSuccess: false,
		},
		{
			caseDesc:      "valid rekor_server value",
			rekorServer:   "http://localhost:3000",
			expectSuccess: true,
		},
		{
			caseDesc:      "valid URL, invalid scheme",
			rekorServer:   "ldap://localhost:3000",
			expectSuccess: false,
		},
		{
			caseDesc:      "invalid URL",
			rekorServer:   "hteeteepeeColonSlashSlashlocalhost:3000",
			expectSuccess: false,
		},
		{
			caseDesc:      "local path",
			rekorServer:   "/localhost",
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		viper.Reset()
		viper.Set("rekor_server", tc.rekorServer)
		if err := validateRekorServerURL(); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}
	}
}
