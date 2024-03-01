//
// Copyright 2023 The Sigstore Authors.
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

package jar

import (
	"archive/zip"
	"bytes"
	"context"
	"sync"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"github.com/go-openapi/swag"

	jarutils "github.com/sassoftware/relic/lib/signjar"

	fuzzUtils "github.com/sigstore/rekor/pkg/fuzz"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/jar"
)

var initter sync.Once

func FuzzJarCreateProposedEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, propsData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		version := "0.0.1"

		ff := fuzz.NewConsumer(propsData)

		props, cleanup, err := fuzzUtils.CreateProps(ff, "jarV001")
		if err != nil {
			t.Skip()
		}

		defer func() {
			for _, c := range cleanup {
				c()
			}
		}()

		it := jar.New()
		entry, err := it.CreateProposedEntry(context.Background(), version, props)
		if err != nil {
			t.Skip()
		}
		ei, err := types.CreateVersionedEntry(entry)
		if err != nil {
			t.Skip()
		}

		if ok, err := ei.Insertable(); !ok || err != nil {
			t.Errorf("entry created via CreateProposedEntry should be insertable: %v", err)
		}

		if _, err := types.CanonicalizeEntry(context.Background(), ei); err != nil {
			t.Errorf("valid insertable entry should be able to be canonicalized: %v", err)
		}

		_, _ = ei.IndexKeys()
	})
}

func FuzzJarUnmarshalAndCanonicalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, entryData []byte) {
		initter.Do(fuzzUtils.SetFuzzLogger)

		ff := fuzz.NewConsumer(entryData)

		targetV001 := &models.JarV001Schema{}

		if err := ff.GenerateStruct(targetV001); err != nil {
			t.Skip()
		}

		targetEntry := &models.Jar{
			APIVersion: swag.String(APIVERSION),
			Spec:       targetV001,
		}

		ei, err := types.UnmarshalEntry(targetEntry)
		if err != nil {
			t.Skip()
		}

		if _, err := types.CanonicalizeEntry(context.Background(), ei); err != nil {
			t.Skip()
		}
	})
}

type zipFile struct {
	fileName string
	fileBody []byte
}

func FuzzJarutilsVerify(f *testing.F) {
	f.Fuzz(func(_ *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		noOfFiles, err := ff.GetInt()
		if err != nil {
			return
		}
		zipFiles := make([]*zipFile, 0)
		for i := 0; i < noOfFiles%20; i++ {
			fileName, err := ff.GetString()
			if err != nil {
				return
			}
			fileBody, err := ff.GetBytes()
			if err != nil {
				return
			}
			zf := &zipFile{
				fileName: fileName,
				fileBody: fileBody,
			}
			zipFiles = append(zipFiles, zf)
		}
		if len(zipFiles) == 0 {
			return
		}

		buf := new(bytes.Buffer)
		w := zip.NewWriter(buf)
		for _, file := range zipFiles {
			f, err := w.Create(file.fileName)
			if err != nil {
				w.Close()
				return
			}
			_, err = f.Write([]byte(file.fileBody))
			if err != nil {
				w.Close()
				return
			}
		}

		w.Close()
		zipData := buf.Bytes()
		zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err != nil {
			return
		}
		_, _ = jarutils.Verify(zipReader, false)
	})
}
