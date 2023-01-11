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
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestIdentities(t *testing.T) {
	// from ssh_e2e_test.go
	publicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXofkiahE7uavjWvxnwkUF27qMgz7pdTwzSv0XzVG6EtirOv3PDWct4YKoXE9c0EqbxnIfYEKwEextdvB7zkgwczdJSHxf/18jQumLn/FuoCmugVSk1H5Qli/qzwBpaTnOk3WuakGuoYUl8ZAokKKgOKLA0aZJ1WRQ2ZCZggA3EkwNZiY17y9Q6HqdgQcH6XN8aAMADNVJdMAJb33hSRJjjsAPTmzBTishP8lYDoGRSsSE7/8XRBCEV5E4I8mI9GElcZwV/1KJx98mpH8QvMzXM1idFcwPRtt1NTAOshwgUU0Fu1x8lU5RQIa6ZKW36qNQLvLxy/BscC7B/mdLptoDs/ot9NimUXZcgCR1a2Q3o7Wi6jIgcgJcyV10Nba81ol4RdN4qPHnVZIzuo+dBkqwG3CMtB4Rj84+Qi+7zyU01hIPreoxQDXaayiGPBUUIiAlW9gsiuRWJzNnu3cvuWDLVfQIkjh7Wug58z+v2NOJ7IMdyERillhzDcvVHaq14+U= test@rekor.dev"

	pub, err := NewPublicKey(strings.NewReader(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	identities, err := pub.Identities()
	if err != nil {
		t.Fatalf("unexpected error getting identities: %v", err)
	}

	expectedIDs := []string{"test@rekor.dev",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXofkiahE7uavjWvxnwkUF27qMgz7pdTwzSv0XzVG6EtirOv3PDWct4YKoXE9c0EqbxnIfYEKwEextdvB7zkgwczdJSHxf/18jQumLn/FuoCmugVSk1H5Qli/qzwBpaTnOk3WuakGuoYUl8ZAokKKgOKLA0aZJ1WRQ2ZCZggA3EkwNZiY17y9Q6HqdgQcH6XN8aAMADNVJdMAJb33hSRJjjsAPTmzBTishP8lYDoGRSsSE7/8XRBCEV5E4I8mI9GElcZwV/1KJx98mpH8QvMzXM1idFcwPRtt1NTAOshwgUU0Fu1x8lU5RQIa6ZKW36qNQLvLxy/BscC7B/mdLptoDs/ot9NimUXZcgCR1a2Q3o7Wi6jIgcgJcyV10Nba81ol4RdN4qPHnVZIzuo+dBkqwG3CMtB4Rj84+Qi+7zyU01hIPreoxQDXaayiGPBUUIiAlW9gsiuRWJzNnu3cvuWDLVfQIkjh7Wug58z+v2NOJ7IMdyERillhzDcvVHaq14+U="}

	sort.Strings(identities)
	sort.Strings(expectedIDs)
	if !reflect.DeepEqual(identities, expectedIDs) {
		t.Errorf("err getting identities from keys, got %v, expected %v", identities, expectedIDs)
	}
}
