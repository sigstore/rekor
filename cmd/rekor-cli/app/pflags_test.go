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
	"net/http"
	"net/http/httptest"
	"os"
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
		multiPublicKey        []string
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
				file, err = os.ReadFile("tests/test_file.txt")
			case "/signature":
				file, err = os.ReadFile("tests/test_file.sig")
			case "/publicKey":
				file, err = os.ReadFile("tests/test_public_key.key")
			case "/rekord":
				file, err = os.ReadFile("tests/rekor.json")
			case "/rpmEntry":
				file, err = os.ReadFile("tests/rpm.json")
			case "/rpm":
				file, err = os.ReadFile("tests/test.rpm")
			case "/rpmPublicKey":
				file, err = os.ReadFile("tests/test_rpm_public_key.key")
			case "/alpine":
				file, err = os.ReadFile("tests/test_alpine.apk")
			case "/alpinePublicKey":
				file, err = os.ReadFile("tests/test_alpine.pub")
			case "/alpineEntry":
				file, err = os.ReadFile("tests/alpine.json")
			case "/helmEntry":
				file, err = os.ReadFile("tests/helm.json")
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
			entry:                 "tests/rekor.json",
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
			entry:                 "tests/rekor.json",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid rpm file",
			entry:                 "tests/rpm.json",
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
			entry:                 "tests/rpm.json",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "non-existent rekord file",
			entry:                 "tests/not_there.json",
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
			artifact:              "tests/test_file.txt",
			signature:             "tests/test_file.sig",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rpm - local artifact with required flags",
			typeStr:               "rpm",
			artifact:              "tests/test.rpm",
			publicKey:             "tests/test_rpm_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid alpine - local artifact with required flags",
			typeStr:               "alpine",
			artifact:              "tests/test_alpine.apk",
			publicKey:             "tests/test_alpine.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "nonexistent local artifact",
			artifact:              "tests/not_a_file",
			signature:             "tests/test_file.sig",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistent remote artifact",
			artifact:              testServer.URL + "/not_found",
			signature:             "tests/test_file.sig",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact without required local signature",
			artifact:              "tests/test_file.txt",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with missing remote signature",
			artifact:              "tests/test_file.txt",
			publicKey:             "tests/test_public_key.key",
			signature:             testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid local signature",
			artifact:              "tests/test_file.txt",
			signature:             "tests/not_a_file",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid remote signature",
			artifact:              "tests/test_file.txt",
			signature:             testServer.URL + "/artifact",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact without required public key",
			artifact:              "tests/test_file.txt",
			signature:             "tests/test_file.sig",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid local public key",
			artifact:              "tests/test_file.txt",
			signature:             "tests/test_file.sig",
			publicKey:             "tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "local artifact with invalid remote public key",
			artifact:              "tests/test_file.txt",
			signature:             "tests/test_file.sig",
			publicKey:             testServer.URL + "/artifact",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid rekord - remote artifact with required flags",
			artifact:              testServer.URL + "/artifact",
			signature:             "tests/test_file.sig",
			publicKey:             "tests/test_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid rpm - remote artifact with required flags",
			typeStr:               "rpm",
			artifact:              testServer.URL + "/rpm",
			publicKey:             "tests/test_rpm_public_key.key",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid alpine - remote artifact with required flags",
			typeStr:               "alpine",
			artifact:              testServer.URL + "/alpine",
			publicKey:             "tests/test_alpine.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "remote artifact with invalid URL",
			artifact:              "hteeteep%**/test_file.txt",
			signature:             "tests/test_file.sig",
			publicKey:             "tests/test_public_key.key",
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
			artifact:              "tests/test_cose.cbor",
			publicKey:             "tests/test_cose.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
			aad:                   "dGVzdCBhYWQ=",
		},
		{
			caseDesc:              "valid cose, malformed base64 aad",
			typeStr:               "cose",
			artifact:              "tests/test_cose.cbor",
			publicKey:             "tests/test_cose.pub",
			expectParseSuccess:    false,
			expectValidateSuccess: true,
			aad:                   "dGVzdCBhYWQ]",
		},
		{
			caseDesc:              "valid cose, missing aad",
			typeStr:               "cose",
			artifact:              "tests/test_cose.cbor",
			publicKey:             "tests/test_cose.pub",
			expectParseSuccess:    true,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "valid intoto - one keys",
			typeStr:               "intoto",
			artifact:              "tests/intoto_dsse.json",
			publicKey:             "tests/intoto_dsse.pem",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid intoto - multi keys",
			typeStr:               "intoto",
			artifact:              "tests/intoto_multi_dsse.json",
			multiPublicKey:        []string{"tests/intoto_dsse.pem", "tests/intoto_multi_pub2.pem"},
			expectParseSuccess:    true,
			expectValidateSuccess: true,
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
		if len(tc.multiPublicKey) > 0 {
			for _, key := range tc.multiPublicKey {
				args = append(args, "--public-key", key)
			}
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

// TestValidateRetryCount tests the validation of the retry count flag
func TestValidateRetryCount(t *testing.T) {
	type test struct {
		caseDesc      string
		retryCount    string
		expectSuccess bool
	}

	tests := []test{
		{
			caseDesc:      "value not specified",
			expectSuccess: false,
		},
		{
			caseDesc:      "valid retry_count value: 0",
			retryCount:    "0",
			expectSuccess: true,
		},
		{
			caseDesc:      "valid retry_count value: 1",
			retryCount:    "1",
			expectSuccess: true,
		},
		{
			caseDesc:      "invalid retry_count value: asdf",
			retryCount:    "asdf",
			expectSuccess: false,
		},
		{
			caseDesc:      "invalid retry_count value: -1",
			retryCount:    "-1",
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		if err := rootCmd.PersistentFlags().Set("retry", tc.retryCount); (err == nil) != tc.expectSuccess {
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
				file, err = os.ReadFile("../../../tests/test_file.txt")
			case "/publicKey":
				file, err = os.ReadFile("../../../tests/test_public_key.key")
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
			caseDesc:              "nonexistent local artifact",
			artifact:              "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistent remote artifact",
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
			caseDesc:              "nonexistent local public key",
			publicKey:             "../../../tests/not_a_file",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "nonexistent remote public key",
			publicKey:             testServer.URL + "/not_found",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA1",
			sha:                   "84374135959eacf60cf3fed7520a01b336332efe",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA1 with prefix",
			sha:                   "sha1:84374135959eacf60cf3fed7520a01b336332efe",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA256",
			sha:                   "45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA256 with prefix",
			sha:                   "sha256:45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA512",
			sha:                   "a5d575f245588b64bcec78a1bb9d92a66bfb4d68d7de1aea4162ad0b232753860cb764fd0645ada1f5d935163522987359e515e0594068d7bc108f0584d6da29",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "valid SHA512 with prefix",
			sha:                   "sha512:a5d575f245588b64bcec78a1bb9d92a66bfb4d68d7de1aea4162ad0b232753860cb764fd0645ada1f5d935163522987359e515e0594068d7bc108f0584d6da29",
			expectParseSuccess:    true,
			expectValidateSuccess: true,
		},
		{
			caseDesc:              "invalid SHA prefix",
			sha:                   "sha257:45c7b11fcbf07dec1694adecd8c5b85770a12a6c8dfdcf2580a2db0c47c31779",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "invalid SHA",
			sha:                   "45c7b11fcbf",
			expectParseSuccess:    false,
			expectValidateSuccess: false,
		},
		{
			caseDesc:              "invalid hash alg",
			sha:                   "md5:d408f34c27cf5930be6394a455f23d40",
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

func TestParseTypeFlag(t *testing.T) {
	type test struct {
		caseDesc      string
		typeStr       string
		expectSuccess bool
	}

	tests := []test{
		{
			caseDesc:      "bogus",
			typeStr:       "bogus",
			expectSuccess: false,
		},
		{
			caseDesc:      "rekord",
			typeStr:       "rekord",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit rekord v0.0.1",
			typeStr:       "rekord:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent rekord v0.0.0",
			typeStr:       "rekord:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "hashedrekord",
			typeStr:       "hashedrekord",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit hashedrekord v0.0.1",
			typeStr:       "hashedrekord:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent hashedrekord v0.0.0",
			typeStr:       "hashedrekord:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "alpine",
			typeStr:       "alpine",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit alpine v0.0.1",
			typeStr:       "alpine:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent alpine v0.0.0",
			typeStr:       "alpine:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "cose",
			typeStr:       "cose",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit cose v0.0.1",
			typeStr:       "cose:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent cose v0.0.0",
			typeStr:       "cose:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "helm",
			typeStr:       "helm",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit helm v0.0.1",
			typeStr:       "helm:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent helm v0.0.0",
			typeStr:       "helm:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "intoto",
			typeStr:       "intoto",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit intoto v0.0.1",
			typeStr:       "intoto:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit intoto v0.0.2",
			typeStr:       "intoto:0.0.2",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent intoto v0.0.0",
			typeStr:       "intoto:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "jar",
			typeStr:       "jar",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit jar v0.0.1",
			typeStr:       "jar:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent jar v0.0.0",
			typeStr:       "jar:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "rfc3161",
			typeStr:       "rfc3161",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit rfc3161 v0.0.1",
			typeStr:       "rfc3161:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent rfc3161 v0.0.0",
			typeStr:       "rfc3161:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "rpm",
			typeStr:       "rpm",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit rpm v0.0.1",
			typeStr:       "rpm:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent rpm v0.0.0",
			typeStr:       "rpm:0.0.0",
			expectSuccess: false,
		},
		{
			caseDesc:      "tuf",
			typeStr:       "tuf",
			expectSuccess: true,
		},
		{
			caseDesc:      "explicit tuf v0.0.1",
			typeStr:       "tuf:0.0.1",
			expectSuccess: true,
		},
		{
			caseDesc:      "non-existent tuf v0.0.0",
			typeStr:       "tuf:0.0.0",
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		if _, _, err := ParseTypeFlag(tc.typeStr); (err == nil) != tc.expectSuccess {
			t.Fatalf("unexpected error parsing type flag in '%v': %v", tc.caseDesc, err)
		}
	}
}
