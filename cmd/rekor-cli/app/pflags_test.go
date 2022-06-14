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

package app

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/pkg/types"
)

func TestArtifactPFlags(t *testing.T) {
	type test struct {
		caseDesc              string
		typeStr               string
		entry                 string
		artifact              string
		signature             string
		publicKey             string
		uuid                  string
		aad                   string
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
			case "/rpmEntry":
				file, err = ioutil.ReadFile("../../../tests/rpm.json")
			case "/rpm":
				file, err = ioutil.ReadFile("../../../tests/test.rpm")
			case "/rpmPublicKey":
				file, err = ioutil.ReadFile("../../../tests/test_rpm_public_key.key")
			case "/alpine":
				file, err = ioutil.ReadFile("../../../tests/test_alpine.apk")
			case "/alpinePublicKey":
				file, err = ioutil.ReadFile("../../../tests/test_alpine.pub")
			case "/alpineEntry":
				file, err = ioutil.ReadFile("../../../tests/alpine.json")
			case "/helmEntry":
				file, err = ioutil.ReadFile("../../../tests/helm.json")
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
			entry:                 "../../../tests/rekor.json",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rekord URL",
			entry:                 testServer.URL + "/rekord",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rekord file, wrong type",
			typeStr:               "rpm",
			entry:                 "../../../tests/rekor.json",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid rpm file",
			entry:                 "../../../tests/rpm.json",
			typeStr:               "rpm",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rpm URL",
			entry:                 testServer.URL + "/rpmEntry",
			typeStr:               "rpm",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid alpine URL",
			entry:                 testServer.URL + "/alpineEntry",
			typeStr:               "alpine",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid helm URL",
			entry:                 testServer.URL + "/helmEntry",
			typeStr:               "helm",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},

		{
			caseDesc:              "valid rpm file, wrong type",
			typeStr:               "rekord",
			entry:                 "../../../tests/rpm.json",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "non-existent rekord file",
			entry:                 "../../../tests/not_there.json",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "non-existent rekord url",
			entry:                 testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid rekord - local artifact with required flags",
			artifact:              "../../../tests/test_file.txt",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rpm - local artifact with required flags",
			typeStr:               "rpm",
			artifact:              "../../../tests/test.rpm",
			publicKey:             "../../../tests/test_rpm_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid alpine - local artifact with required flags",
			typeStr:               "alpine",
			artifact:              "../../../tests/test_alpine.apk",
			publicKey:             "../../../tests/test_alpine.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
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
			caseDesc:              "valid rekord - remote artifact with required flags",
			artifact:              testServer.URL + "/artifact",
			signature:             "../../../tests/test_file.sig",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rpm - remote artifact with required flags",
			typeStr:               "rpm",
			artifact:              testServer.URL + "/rpm",
			publicKey:             "../../../tests/test_rpm_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid alpine - remote artifact with required flags",
			typeStr:               "alpine",
			artifact:              testServer.URL + "/alpine",
			publicKey:             "../../../tests/test_alpine.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "remote artifact with invalid URL",
			artifact:              "hteeteep%**/test_file.txt",
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
		{
			caseDesc:              "valid cose, with aad",
			typeStr:               "cose",
			artifact:              "../../../tests/test_cose.cbor",
			publicKey:             "../../../tests/test_cose.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			aad:                   "dGVzdCBhYWQ=",
		},
		{
			caseDesc:              "valid cose, missing aad",
			typeStr:               "cose",
			artifact:              "../../../tests/test_cose.cbor",
			publicKey:             "../../../tests/test_cose.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
	}

	for _, tc := range tests {
		initializePFlagMap()
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

		if tc.entry != "" {
			args = append(args, "--entry", tc.entry)
		}
		if tc.typeStr != "" {
			args = append(args, "--type", tc.typeStr)
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
		if tc.uuid != "" {
			args = append(args, "--uuid", tc.uuid)
		}
		if tc.logIndex != "" {
			args = append(args, "--log-index", tc.logIndex)
		}
		if tc.aad != "" {
			args = append(args, "--aad", tc.aad)
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
			if !tc.uuidRequired && !tc.logIndexRequired && tc.entry == "" {
				typeStr, versionStr, err := ParseTypeFlag(viper.GetString("type"))
				if err != nil {
					t.Errorf("error parsing typeStr: %v", err)
				}
				props := CreatePropsFromPflags()
				if _, err := types.NewProposedEntry(context.Background(), typeStr, versionStr, *props); err != nil {
					t.Errorf("unexpected result in '%v' building entry: %v", tc.caseDesc, err)
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

func TestSearchPFlags(t *testing.T) {
	type test struct {
		caseDesc              string
		artifact              string
		publicKey             string
		sha                   string
		email                 string
		pkiFormat             string
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
			case "/publicKey":
				file, err = ioutil.ReadFile("../../../tests/test_public_key.key")
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
			caseDesc:              "valid local artifact",
			artifact:              "../../../tests/test_file.txt",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid remote artifact",
			artifact:              testServer.URL + "/artifact",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "nonexistant local artifact",
			artifact:              "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistant remote artifact",
			artifact:              testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid local public key",
			publicKey:             "../../../tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid local minisign public key",
			publicKey:             "../../../pkg/pki/minisign/testdata/minisign.pub",
			pkiFormat:             "minisign",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid remote public key",
			publicKey:             testServer.URL + "/publicKey",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "nonexistant local public key",
			publicKey:             "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistant remote public key",
			publicKey:             testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA",
			sha:                   "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "invalid SHA",
			sha:                   "45c7b11fcbf",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid email",
			email:                 "cat@foo.com",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "invalid email",
			email:                 "SignaMeseCat",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "no flags when either artifact, sha, public key, or email are needed",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
	}

	for _, tc := range tests {
		initializePFlagMap()
		var blankCmd = &cobra.Command{}
		if err := addSearchPFlags(blankCmd); err != nil {
			t.Fatalf("unexpected error adding flags in '%v': %v", tc.caseDesc, err)
		}

		args := []string{}

		if tc.artifact != "" {
			args = append(args, "--artifact", tc.artifact)
		}
		if tc.publicKey != "" {
			args = append(args, "--public-key", tc.publicKey)
		}
		if tc.pkiFormat != "" {
			args = append(args, "--pki-format", tc.pkiFormat)
		}
		if tc.sha != "" {
			args = append(args, "--sha", tc.sha)
		}
		if tc.email != "" {
			args = append(args, "--email", tc.email)
		}

		if err := blankCmd.ParseFlags(args); (err == nil) != tc.expectParseSuccess {
			t.Errorf("unexpected result parsing '%v': %v", tc.caseDesc, err)
			continue
		}

		if err := viper.BindPFlags(blankCmd.Flags()); err != nil {
			t.Fatalf("unexpected result initializing viper in '%v': %v", tc.caseDesc, err)
		}
		if err := validateSearchPFlags(); (err == nil) != tc.expectValidateSuccess {
			t.Errorf("unexpected result validating '%v': %v", tc.caseDesc, err)
			continue
		}
	}
}
