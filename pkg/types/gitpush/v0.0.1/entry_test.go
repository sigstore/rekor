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

package gitpush

import (
	"reflect"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/models"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V001Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

var (
	emptyString = ""
	gpgCerts    = []string{`-----BEGIN PGP SIGNATURE-----
An invalid test signature, look at the end boundary!
-----BEGIN PGP SIGNATURE-----`, // invalid

		`-----BEGIN PGP SIGNATURE-----
This is not really valid either, but look! Correct end boundary!
-----END PGP SIGNATURE-----`, // "valid"
	}
	certVersions = []string{
		"certificate version 0.1", // valid
		"certificate version 0.2", // invalid
		"certificate versions 2",  // invalid
	}
	tests = []struct {
		name    string
		it      *models.GitpushV001Schema
		wantErr bool
	}{
		{
			name:    "empty",
			it:      &models.GitpushV001Schema{},
			wantErr: true,
		},
		{
			name: "wrong certificate version",
			it: &models.GitpushV001Schema{
				CertificateVersion: &certVersions[1],
				Nonce:              &emptyString,
				Protocol:           &emptyString,
				Pushee:             &emptyString,
				Pusher:             &emptyString,
				Signature:          &emptyString,
			},
			wantErr: true,
		},
		{
			name: "invalid signature",
			it: &models.GitpushV001Schema{
				CertificateVersion: &certVersions[0],
				Nonce:              &emptyString,
				Protocol:           &emptyString,
				Pushee:             &emptyString,
				Pusher:             &emptyString,
				Signature:          &gpgCerts[0],
			},
			wantErr: true,
		},
		{
			name: "valid signature",
			it: &models.GitpushV001Schema{
				CertificateVersion: &certVersions[0],
				Nonce:              &emptyString,
				Protocol:           &emptyString,
				Pushee:             &emptyString,
				Pusher:             &emptyString,
				Signature:          &gpgCerts[1],
			},
			wantErr: false,
		},
	}
)

func TestV001Entry_Unmarshal(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V001Entry{}
			it := &models.Gitpush{
				Spec: tt.it,
			}
			var uv = func() error {
				if err := v.Unmarshal(it); err != nil {
					return err
				}
				if err := v.Validate(); err != nil {
					return err
				}
				return nil
			}
			if err := uv(); (err != nil) != tt.wantErr {
				t.Errorf("V001Entry.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
