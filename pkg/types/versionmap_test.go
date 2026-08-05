//
// Copyright 2026 The Sigstore Authors.
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

package types

import (
	"testing"
)

func dummyFactory() EntryImpl {
	return nil
}

func TestVersionMap(t *testing.T) {
	vm := NewEntryFactoryMap()
	if vm.Count() != 0 {
		t.Errorf("expected 0 entries, got %d", vm.Count())
	}

	if err := vm.SetEntryFactory("", dummyFactory); err == nil {
		t.Error("expected error setting empty version string")
	}

	if err := vm.SetEntryFactory("0.0.1", dummyFactory); err != nil {
		t.Errorf("unexpected error setting valid version string: %v", err)
	}

	if vm.Count() != 1 {
		t.Errorf("expected 1 entry, got %d", vm.Count())
	}

	versions := vm.SupportedVersions()
	if len(versions) != 1 || versions[0] != "0.0.1" {
		t.Errorf("expected ['0.0.1'], got %v", versions)
	}

	ef, err := vm.GetEntryFactory("0.0.1")
	if err != nil || ef == nil {
		t.Errorf("unexpected error getting factory for 0.0.1: %v", err)
	}

	if _, err := vm.GetEntryFactory("9.9.9"); err == nil {
		t.Error("expected error getting factory for nonexistent version")
	}
}
