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

package ssh

import (
	"encoding/base64"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"golang.org/x/crypto/ssh"
)

func TestIdentities(t *testing.T) {
	// from ssh_e2e_test.go
	publicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXofkiahE7uavjWvxnwkUF27qMgz7pdTwzSv0XzVG6EtirOv3PDWct4YKoXE9c0EqbxnIfYEKwEextdvB7zkgwczdJSHxf/18jQumLn/FuoCmugVSk1H5Qli/qzwBpaTnOk3WuakGuoYUl8ZAokKKgOKLA0aZJ1WRQ2ZCZggA3EkwNZiY17y9Q6HqdgQcH6XN8aAMADNVJdMAJb33hSRJjjsAPTmzBTishP8lYDoGRSsSE7/8XRBCEV5E4I8mI9GElcZwV/1KJx98mpH8QvMzXM1idFcwPRtt1NTAOshwgUU0Fu1x8lU5RQIa6ZKW36qNQLvLxy/BscC7B/mdLptoDs/ot9NimUXZcgCR1a2Q3o7Wi6jIgcgJcyV10Nba81ol4RdN4qPHnVZIzuo+dBkqwG3CMtB4Rj84+Qi+7zyU01hIPreoxQDXaayiGPBUUIiAlW9gsiuRWJzNnu3cvuWDLVfQIkjh7Wug58z+v2NOJ7IMdyERillhzDcvVHaq14+U= test@rekor.dev"
	expectedKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(publicKey))

	pub, err := NewPublicKey(strings.NewReader(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(pub.EmailAddresses(), []string{"test@rekor.dev"}) {
		t.Fatalf("expected email address, got %v", pub.EmailAddresses())
	}
	if !reflect.DeepEqual(pub.Subjects(), []string{"test@rekor.dev"}) {
		t.Fatalf("expected email address as subject, got %v", pub.Subjects())
	}

	keyVal := expectedKey.(ssh.CryptoPublicKey).CryptoPublicKey()
	pkixKey, err := cryptoutils.MarshalPublicKeyToDER(keyVal)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pub.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("too many identities, expected 1, got %v", len(ids))
	}
	if !reflect.DeepEqual(ids[0].Crypto.(ssh.PublicKey).Marshal(), expectedKey.Marshal()) {
		t.Errorf("certificates did not match")
	}
	if !reflect.DeepEqual(ids[0].Raw, pkixKey) {
		t.Errorf("raw identities did not match, expected %v, got %v", string(pkixKey), string(ids[0].Raw))
	}
	// removing "SHA256:" prefix
	fp, _ := base64.RawStdEncoding.DecodeString(ids[0].Fingerprint[7:])
	if len(fp) != 32 {
		t.Errorf("fingerprint is not expected length of 32 (32-byte sha256): %d", len(fp))
	}
}

func randomSuffix(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestPubKeyParsingLimit(t *testing.T) {
	// limit on NewPublicKey should be 65536 bytes, so let's generate a short one first and then extend it to ensure it fails
	publicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXofkiahE7uavjWvxnwkUF27qMgz7pdTwzSv0XzVG6EtirOv3PDWct4YKoXE9c0EqbxnIfYEKwEextdvB7zkgwczdJSHxf/18jQumLn/FuoCmugVSk1H5Qli/qzwBpaTnOk3WuakGuoYUl8ZAokKKgOKLA0aZJ1WRQ2ZCZggA3EkwNZiY17y9Q6HqdgQcH6XN8aAMADNVJdMAJb33hSRJjjsAPTmzBTishP8lYDoGRSsSE7/8XRBCEV5E4I8mI9GElcZwV/1KJx98mpH8QvMzXM1idFcwPRtt1NTAOshwgUU0Fu1x8lU5RQIa6ZKW36qNQLvLxy/BscC7B/mdLptoDs/ot9NimUXZcgCR1a2Q3o7Wi6jIgcgJcyV10Nba81ol4RdN4qPHnVZIzuo+dBkqwG3CMtB4Rj84+Qi+7zyU01hIPreoxQDXaayiGPBUUIiAlW9gsiuRWJzNnu3cvuWDLVfQIkjh7Wug58z+v2NOJ7IMdyERillhzDcvVHaq14+U= "
	randomLongComment := randomSuffix(32768)

	validKey := publicKey + randomLongComment

	if _, err := NewPublicKey(strings.NewReader(validKey)); err != nil {
		t.Errorf("unexpected error parsing valid-length key: %v", err)
	}

	// now we should be exceeding the length
	validKey += randomLongComment

	if _, err := NewPublicKey(strings.NewReader(validKey)); err == nil {
		t.Errorf("expected an error parsing invalid-length key")
	}
}
