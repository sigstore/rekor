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
package rekord

import (
	"crypto/rand"

	"github.com/mitchellh/mapstructure"
	"github.com/projectrekor/rekor/pkg/generated/models"
)

type V001Entry struct {
	rekorObj                models.RekordV001Schema
	fetchedExternalEntities bool
}

const APIVERSION = "0.0.1"

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func (v V001Entry) Unmarshal(e interface{}) error {
	rekord := e.(*models.Rekord)
	if err := mapstructure.Decode(rekord.Spec, &v.rekorObj); err != nil {
		return err
	}
	return v.rekorObj.Validate(nil) //TODO: implement custom field validation for pki content
}

func (v V001Entry) HasExternalEntities() bool {
	return v.fetchedExternalEntities
}

func (v V001Entry) FetchExternalEntities() error {
	if v.fetchedExternalEntities {
		return nil
	}
	//TODO: implement equivalent to types.Load()
	v.fetchedExternalEntities = true
	return nil
}

func (v V001Entry) CanonicalLeaf() ([]byte, error) {
	//TODO: implement equivalent to types.MarshalJSON()
	bytes := make([]byte, 10)
	_, _ = rand.Read(bytes)
	return bytes, nil
}
