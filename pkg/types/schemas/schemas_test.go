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

package schemas

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

/* drops test execution to root of repository to resolve $ref relative to that */
func init() {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../../")
	if err := os.Chdir(dir); err != nil {
		panic(err)
	}
}

func TestSchemaWellFormed(t *testing.T) {

	err := filepath.Walk("pkg/types/schemas/base_schema", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Error(err)
		}
		if strings.HasSuffix(path, ".json") {
			schemaLoader := gojsonschema.NewReferenceLoader("file://" + path)
			if _, err := gojsonschema.NewSchema(schemaLoader); err != nil {
				t.Error(err)
			}
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
