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

package util

import (
	"testing"
)

// validSignedNote is a signed note with one signature; the 4-byte key-hash
// prefix plus a 64-byte ed25519-sized signature base64-encoded.
const validSignedNote = "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n"

// validSignedNoteTwoSigs has two signature lines.
const validSignedNoteTwoSigs = "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n\u2014 another_name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n"

// FuzzSignedNoteRoundTrip checks that any byte sequence accepted by
// SignedNote.UnmarshalText re-serializes to something the parser still accepts.
// This catches divergence between the hand-rolled parser (fmt.Fscanf, base64,
// 4-byte hash slicing) and the String() serializer.
func FuzzSignedNoteRoundTrip(f *testing.F) {
	f.Add([]byte(validSignedNote))
	f.Add([]byte(validSignedNoteTwoSigs))

	f.Fuzz(func(t *testing.T, data []byte) {
		sn := &SignedNote{}
		if err := sn.UnmarshalText(data); err != nil {
			return
		}
		out, err := sn.MarshalText()
		if err != nil {
			t.Fatalf("unmarshalled note failed to marshal: %v", err)
		}
		sn2 := &SignedNote{}
		if err := sn2.UnmarshalText(out); err != nil {
			t.Fatalf("round-trip parse failed: %v\ninput: %q\nremarshalled: %q", err, data, out)
		}
	})
}

// FuzzCheckpointRoundTrip checks the same property for the inner Checkpoint
// body (origin / size / root-hash / other-content lines).
func FuzzCheckpointRoundTrip(f *testing.F) {
	f.Add([]byte("Banana Checkpoint v5\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n"))
	f.Add([]byte("Log Checkpoint v0\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\nHere's some associated data.\n"))
	f.Add([]byte("Banana Checkpoint v7\n9943\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\nfoo\nbar\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := &Checkpoint{}
		if err := c.UnmarshalCheckpoint(data); err != nil {
			return
		}
		out, err := c.MarshalCheckpoint()
		if err != nil {
			t.Fatalf("unmarshalled checkpoint failed to marshal: %v", err)
		}
		c2 := &Checkpoint{}
		if err := c2.UnmarshalCheckpoint(out); err != nil {
			t.Fatalf("round-trip parse failed: %v\ninput: %q\nremarshalled: %q", err, data, out)
		}
	})
}

// FuzzSignedCheckpoint exercises the composed SignedCheckpoint.UnmarshalText
// path that clients use when validating log responses.
func FuzzSignedCheckpoint(f *testing.F) {
	f.Add([]byte(validSignedNote))
	f.Add([]byte(validSignedNoteTwoSigs))

	f.Fuzz(func(_ *testing.T, data []byte) {
		sc := &SignedCheckpoint{}
		_ = sc.UnmarshalText(data)
	})
}
