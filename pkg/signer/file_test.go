/*
Copyright The Rekor Authors.

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

package signer

import (
	"os"
	"path/filepath"
	"testing"
)

const testEcdsaKey = `
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1ee56fe067d83265fe430391edfa6586

W5NqqRe5rOVe4OvxehYKm6wscR1JFoyRyd8M+Rutp8Q2lxPuKFhR4FZ61b0yy6pr
LGJGQWOTIZxrNZ8g4JeS9I3huDWGloZRI2fbTg69HK4EiQQWUc1wS1TWAVoaf4fr
LclBWxp2UzqHDaNJ0/2DoGFZhaeMU84VA1O41lO+p5Cx4bms0yWeEHwOrf2AmnNY
l5Zm9zoPpXxaDEPSTs5c1loRmmxPHKgb68oZPxEnsCg=
-----END EC PRIVATE KEY-----`

func TestFile(t *testing.T) {
	testKeyPass := `password123`
	td := t.TempDir()
	keyFile := filepath.Join(td, "ecdsa-key.pem")
	if err := os.WriteFile(keyFile, []byte(testEcdsaKey), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		keyPath string
		keyPass string
		wantErr bool
	}{
		{
			name:    "valid ecdsa",
			keyPath: keyFile,
			keyPass: testKeyPass,
			wantErr: false,
		},
		{
			name:    "invalid pass",
			keyPath: keyFile,
			keyPass: "123",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			_, err := NewFile(tc.keyPath, tc.keyPass)
			if tc.wantErr != (err != nil) {
				t.Errorf("NewFile() expected %t, got err %s", tc.wantErr, err)
			}
		})
	}
}
