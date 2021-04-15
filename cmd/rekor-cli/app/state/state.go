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

package state

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/trillian/types"
	"github.com/mitchellh/go-homedir"
)

type persistedState map[string]*types.LogRootV1

func Dump(url string, lr *types.LogRootV1) error {
	rekorDir, err := getRekorDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(rekorDir, "state.json")

	state := loadStateFile()
	if state == nil {
		state = make(persistedState)
	}
	state[url] = lr

	b, err := json.Marshal(&state)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(statePath, b, 0600); err != nil {
		return err
	}
	return nil
}

func loadStateFile() persistedState {
	rekorDir, err := getRekorDir()
	if err != nil {
		return nil
	}
	fp := filepath.Join(rekorDir, "state.json")
	b, err := ioutil.ReadFile(filepath.Clean(fp))
	if err != nil {
		return nil
	}
	result := persistedState{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil
	}
	return result
}

func Load(url string) *types.LogRootV1 {
	if state := loadStateFile(); state != nil {
		return state[url]
	}
	return nil
}

func getRekorDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	rekorDir := filepath.Join(home, ".rekor")
	if _, err := os.Stat(rekorDir); os.IsNotExist(err) {
		if err := os.MkdirAll(rekorDir, 0750); err != nil {
			return "", err
		}
	}
	return rekorDir, nil
}
