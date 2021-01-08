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
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

func TestArtifactPFlags(t *testing.T) {
	type test struct {
		caseDesc              string
		rekord                string
		artifact              string
		signature             string
		publicKey             string
		sha                   string
		uuid                  string
		uuidRequired          bool
		logIndex              string
		logIndexRequired      bool
		expectParseSuccess    bool
		expectValidateSuccess bool
	}

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file := []byte{}
			var err error

			switch r.URL.Path {
			case "/artifact":
				file, err = ioutil.ReadFile("../../../tests/test_file.txt")
			case "/signature":
				file, err = ioutil.ReadFile("../../../tests/test_file.sig")
			case "/publicKey":
				file, err = ioutil.ReadFile("../../../tests/test_public_key.key")
			case "/rekord":
				file, err = ioutil.ReadFile("../../../tests/rekor.json")
			case "/not_found":
				err = errors.New("file not found")
			}
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
			caseDesc:              "valid rekord file",
			rekord:                "../../../tests/rekor.json",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rekord URL",
			rekord:                testServer.URL + "/rekord",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "non-existant rekord file",
			rekord:                "../../../tests/not_there.json",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "non-existant rekord url",
			rekord:                testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid local artifact with required flags",
			artifact:              "../../../tests/test_file.txt",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid local artifact with incorrect length hex SHA value",
			artifact:              "../../../tests/test_file.txt",
			sha:                   "12345abcde",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid remote artifact with incorrect length hex SHA value",
			artifact:              testServer.URL + "/artifact",
			sha:                   "12345abcde",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistant local artifact",
			artifact:              "../../../tests/not_a_file",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistant remote artifact",
			artifact:              testServer.URL + "/not_found",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact without required local signature",
			artifact:              "../../../tests/test_file.txt",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with missing remote signature",
			artifact:              "../../../tests/test_file.txt",
			publicKey:             "../../../tests/test_public_key.key",
			signature:             testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid local signature",
			artifact:              "../../../tests/test_file.txt",
			signature:             "../../../tests/not_a_file",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid remote signature",
			artifact:              "../../../tests/test_file.txt",
			signature:             testServer.URL + "/artifact",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact without required public key",
			artifact:              "../../../tests/test_file.txt",
			signature:             "../../../tests/test_file.sig",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid local public key",
			artifact:              "../../../tests/test_file.txt",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid remote public key",
			artifact:              "../../../tests/test_file.txt",
			signature:             "../../../tests/test_file.sig",
			publicKey:             testServer.URL + "/artifact",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid remote artifact with required flags",
			artifact:              testServer.URL + "/artifact",
			sha:                   "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "remote artifact with invalid URL",
			artifact:              "hteeteep%**/test_file.txt",
			sha:                   "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "remote artifact without required sha",
			artifact:              testServer.URL + "/artifact",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "remote artifact with invalid sha",
			artifact:              testServer.URL + "/artifact",
			sha:                   "1345not%hash%",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid uuid",
			uuid:                  "3030303030303030303030303030303030303030303030303030303030303030",
			uuidRequired:          true,
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "invalid uuid",
			uuid:                  "not_a_uuid",
			uuidRequired:          true,
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "unwanted uuid",
			uuid:                  "3030303030303030303030303030303030303030303030303030303030303030",
			uuidRequired:          false,
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid log index",
			logIndex:              "1",
			logIndexRequired:      true,
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "invalid log index",
			logIndex:              "not_a_int",
			logIndexRequired:      true,
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "invalid log index - less than 0",
			logIndex:              "-1",
			logIndexRequired:      true,
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "unwanted log index",
			logIndex:              "1",
			logIndexRequired:      false,
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "no flags when either uuid, rekord, or artifact++ are needed",
			uuidRequired:          false,
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "missing uuid flag when it is needed",
			uuidRequired:          true,
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "missing log index flag when it is needed",
			logIndexRequired:      true,
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
	}

	for _, tc := range tests {
		var blankCmd = &cobra.Command{}
		if err := addArtifactPFlags(blankCmd); err != nil {
			t.Fatalf("unexpected error adding flags in '%v': %v", tc.caseDesc, err)
		}
		if err := addUUIDPFlags(blankCmd, tc.uuidRequired); err != nil {
			t.Fatalf("unexpected error adding uuid flags in '%v': %v", tc.caseDesc, err)
		}
		if err := addLogIndexFlag(blankCmd, tc.logIndexRequired); err != nil {
			t.Fatalf("unexpected error adding log index flags in '%v': %v", tc.caseDesc, err)
		}

		args := []string{}

		if tc.rekord != "" {
			args = append(args, "--rekord", tc.rekord)
		}
		if tc.artifact != "" {
			args = append(args, "--artifact", tc.artifact)
		}
		if tc.signature != "" {
			args = append(args, "--signature", tc.signature)
		}
		if tc.publicKey != "" {
			args = append(args, "--public-key", tc.publicKey)
		}
		if tc.sha != "" {
			args = append(args, "--sha", tc.sha)
		}
		if tc.uuid != "" {
			args = append(args, "--uuid", tc.uuid)
		}
		if tc.logIndex != "" {
			args = append(args, "--log-index", tc.logIndex)
		}

		if err := blankCmd.ParseFlags(args); (err == nil) != tc.expectParseSuccess {
			t.Errorf("unexpected result parsing '%v': %v", tc.caseDesc, err)
			continue
		}

		if tc.expectValidateSuccess {
			if err := viper.BindPFlags(blankCmd.Flags()); err != nil {
				t.Fatalf("unexpected result initializing viper in '%v': %v", tc.caseDesc, err)
			}
			if err := validateArtifactPFlags(tc.uuidRequired, tc.logIndexRequired); (err == nil) != tc.expectValidateSuccess {
				t.Errorf("unexpected result validating '%v': %v", tc.caseDesc, err)
				continue
			}
			if !tc.uuidRequired && !tc.logIndexRequired {
				if _, err := CreateRekordFromPFlags(); err != nil {
					t.Errorf("unexpected result in '%v' building Rekord: %v", tc.caseDesc, err)
				}
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
		if err := rootCmd.PersistentFlags().Set("rekor_server", tc.rekorServer); (err == nil) != tc.expectSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}
	}
}
