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

// +build e2e

package e2e

import (
	"io/ioutil"
	"testing"

	"github.com/theupdateframework/go-tuf"
)

func generateTestRepo(t *testing.T, files map[string][]byte) tuf.LocalStore {
	store := tuf.MemoryStore(nil, files)
	repo, err := tuf.NewRepo(store)
	if err := repo.Init(false); err != nil {
		t.Fatalf("unexpected error")
	}
	if err != nil {
		t.Fatalf("unexpected error")
	}
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		_, err := repo.GenKey(role)
		if err != nil {
			t.Fatalf("unexpected error")
		}
	}
	for file := range files {
		repo.AddTarget(file, nil)
	}
	repo.Snapshot(tuf.CompressionTypeNone)
	repo.Timestamp()
	repo.Commit()

	return store
}

// createTufSignedArtifact gets the test dir setup correctly with some random artifacts and keys.
func createTufSignedArtifact(t *testing.T, artifactPath, rootPath string) {
	t.Helper()

	store := generateTestRepo(t, map[string][]byte{
		"foo.txt": []byte("foo")})
	meta, err := store.GetMeta()
	if err != nil {
		t.Fatal(err)
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		t.Fatal(err)
	}
	timestampJSON, ok := meta["timestamp.json"]
	if !ok {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(artifactPath, timestampJSON, 0644); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(rootPath, rootJSON, 0644); err != nil {
		t.Fatal(err)
	}
}
