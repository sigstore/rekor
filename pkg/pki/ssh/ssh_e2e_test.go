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

//go:build e2e

package ssh

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

var (
	// Generated with "ssh-keygen -C test@rekor.dev -f id_rsa"
	privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`
	publicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXofkiahE7uavjWvxnwkUF27qMgz7pdTwzSv0XzVG6EtirOv3PDWct4YKoXE9c0EqbxnIfYEKwEextdvB7zkgwczdJSHxf/18jQumLn/FuoCmugVSk1H5Qli/qzwBpaTnOk3WuakGuoYUl8ZAokKKgOKLA0aZJ1WRQ2ZCZggA3EkwNZiY17y9Q6HqdgQcH6XN8aAMADNVJdMAJb33hSRJjjsAPTmzBTishP8lYDoGRSsSE7/8XRBCEV5E4I8mI9GElcZwV/1KJx98mpH8QvMzXM1idFcwPRtt1NTAOshwgUU0Fu1x8lU5RQIa6ZKW36qNQLvLxy/BscC7B/mdLptoDs/ot9NimUXZcgCR1a2Q3o7Wi6jIgcgJcyV10Nba81ol4RdN4qPHnVZIzuo+dBkqwG3CMtB4Rj84+Qi+7zyU01hIPreoxQDXaayiGPBUUIiAlW9gsiuRWJzNnu3cvuWDLVfQIkjh7Wug58z+v2NOJ7IMdyERillhzDcvVHaq14+U= test@rekor.dev
`
)

func SSHSign(t *testing.T, m io.Reader) []byte {
	t.Helper()
	data, err := ioutil.ReadAll(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(privateKey, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(sig)
}
