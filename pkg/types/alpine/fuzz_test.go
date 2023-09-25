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

package alpine

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/viper"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	utils "github.com/sigstore/rekor/pkg/fuzz"
)

func init() {
	viper.Set("max_apk_metadata_size", 60000)
	if viper.GetUint64("max_apk_metadata_size") != 60000 {
		panic(fmt.Sprintf("max metadata size is not defined: %d", viper.GetUint64("max_apk_metadata_size")))
	}
}

// FuzzPackageUnmarshal implements the fuzz test
func FuzzPackageUnmarshal(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		artifactBytes, err := utils.AlpineArtifactBytes(ff)
		if err != nil {
			t.Skip()
		}

		p := &Package{}
		p.Unmarshal(bytes.NewReader(artifactBytes))
	})
}
