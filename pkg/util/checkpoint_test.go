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

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/mod/sumdb/note"
)

// heavily borrowed from https://github.com/google/trillian-examples/blob/master/formats/log/checkpoint_test.go

func TestMarshalCheckpoint(t *testing.T) {
	for _, test := range []struct {
		c    Checkpoint
		want string
	}{
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			want: "Log Checkpoint v0\n123\nYmFuYW5hcw==\n",
		}, {
			c: Checkpoint{
				Ecosystem: "Banana Checkpoint v5",
				Size:      9944,
				Hash:      []byte("the view from the tree tops is great!"),
			},
			want: "Banana Checkpoint v5\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
		}, {
			c: Checkpoint{
				Ecosystem:    "Banana Checkpoint v7",
				Size:         9943,
				Hash:         []byte("the view from the tree tops is great!"),
				OtherContent: []string{"foo", "bar"},
			},
			want: "Banana Checkpoint v7\n9943\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\nfoo\nbar\n",
		},
	} {
		t.Run(string(test.c.Hash), func(t *testing.T) {
			got, err := test.c.MarshalText()
			if err != nil {
				t.Fatalf("unexpected error marshalling: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("Marshal = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUnmarshalCheckpoint(t *testing.T) {
	for _, test := range []struct {
		desc    string
		m       string
		want    Checkpoint
		wantErr bool
	}{
		{
			desc: "valid one",
			m:    "Log Checkpoint v0\n123\nYmFuYW5hcw==\n",
			want: Checkpoint{
				Ecosystem: "Log Checkpoint v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
		}, {
			desc: "valid with different ecosystem",
			m:    "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			want: Checkpoint{
				Ecosystem: "Banana Checkpoint v1",
				Size:      9944,
				Hash:      []byte("the view from the tree tops is great!"),
			},
		}, {
			desc: "valid with trailing data",
			m:    "Log Checkpoint v0\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\nHere's some associated data.\n",
			want: Checkpoint{
				Ecosystem:    "Log Checkpoint v0",
				Size:         9944,
				Hash:         []byte("the view from the tree tops is great!"),
				OtherContent: []string{"Here's some associated data."},
			},
		}, {
			desc: "valid with multiple trailing data lines",
			m:    "Log Checkpoint v0\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\nlots\nof\nlines\n",
			want: Checkpoint{
				Ecosystem:    "Log Checkpoint v0",
				Size:         9944,
				Hash:         []byte("the view from the tree tops is great!"),
				OtherContent: []string{"lots", "of", "lines"},
			},
		}, {
			desc: "valid with trailing newlines",
			m:    "Log Checkpoint v0\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\n\n",
			want: Checkpoint{
				Ecosystem: "Log Checkpoint v0",
				Size:      9944,
				Hash:      []byte("the view from the tree tops is great!"),
			},
		}, {
			desc:    "invalid - insufficient lines",
			m:       "Head\n9944\n",
			wantErr: true,
		}, {
			desc:    "invalid - empty header",
			m:       "\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantErr: true,
		}, {
			desc:    "invalid - missing newline on roothash",
			m:       "Log Checkpoint v0\n123\nYmFuYW5hcw==",
			wantErr: true,
		}, {
			desc:    "invalid size - not a number",
			m:       "Log Checkpoint v0\nbananas\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantErr: true,
		}, {
			desc:    "invalid size - negative",
			m:       "Log Checkpoint v0\n-34\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantErr: true,
		}, {
			desc:    "invalid size - too large",
			m:       "Log Checkpoint v0\n3438945738945739845734895735\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantErr: true,
		}, {
			desc:    "invalid roothash - not base64",
			m:       "Log Checkpoint v0\n123\nThisIsn'tBase64\n",
			wantErr: true,
		},
	} {
		t.Run(string(test.desc), func(t *testing.T) {
			var got Checkpoint
			var gotErr error
			if gotErr = got.UnmarshalText([]byte(test.m)); (gotErr != nil) != test.wantErr {
				t.Fatalf("Unmarshal = %q, wantErr: %T", gotErr, test.wantErr)
			}
			if diff := cmp.Diff(test.want, got); len(diff) != 0 {
				t.Fatalf("Unmarshalled Checkpoint with diff %s", diff)
			}
			if !test.wantErr != CheckpointValidator(test.m) {
				t.Fatalf("Validator failed for %s", test.desc)
			}
		})
	}
}

func TestSigningRoundtripCheckpoint(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPubKey, edPrivKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		c             Checkpoint
		identity      string
		signer        crypto.Signer
		pubKey        crypto.PublicKey
		opts          crypto.SignerOpts
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint RSA v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        rsaKey,
			pubKey:        rsaKey.Public(),
			opts:          &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256},
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint ECDSA v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        ecdsaKey,
			pubKey:        ecdsaKey.Public(),
			opts:          nil,
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint Ed25519 v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        edPrivKey,
			pubKey:        edPubKey,
			opts:          crypto.Hash(0),
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint Mismatch v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        edPrivKey,
			pubKey:        ecdsaKey.Public(),
			opts:          crypto.Hash(0),
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint Mismatch v1",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        ecdsaKey,
			pubKey:        rsaKey.Public(),
			opts:          &rsa.PSSOptions{Hash: crypto.SHA256},
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint Mismatch v2",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        edPrivKey,
			pubKey:        rsaKey.Public(),
			opts:          &rsa.PSSOptions{Hash: crypto.SHA256},
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			c: Checkpoint{
				Ecosystem: "Log Checkpoint Mismatch v3",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			identity:      "someone",
			signer:        ecdsaKey,
			pubKey:        edPubKey,
			opts:          nil,
			wantSignErr:   false,
			wantVerifyErr: true,
		},
	} {
		t.Run(string(test.c.Ecosystem), func(t *testing.T) {
			text, _ := test.c.MarshalText()
			sc := &SignedNote{
				Note: string(text),
			}
			signer, _ := signature.LoadSigner(test.signer, crypto.SHA256)
			if _, ok := test.signer.(*rsa.PrivateKey); ok {
				signer, _ = signature.LoadRSAPSSSigner(test.signer.(*rsa.PrivateKey), crypto.SHA256, test.opts.(*rsa.PSSOptions))
			}

			_, err := sc.Sign(test.identity, signer, options.WithCryptoSignerOpts(test.opts))
			if (err != nil) != test.wantSignErr {
				t.Fatalf("signing test failed: wantSignErr %v, err %v", test.wantSignErr, err)
			}
			if !test.wantSignErr {
				verifier, _ := signature.LoadVerifier(test.pubKey, crypto.SHA256)
				if _, ok := test.pubKey.(*rsa.PublicKey); ok {
					verifier, _ = signature.LoadRSAPSSVerifier(test.pubKey.(*rsa.PublicKey), crypto.SHA256, test.opts.(*rsa.PSSOptions))
				}

				if !sc.Verify(verifier) != test.wantVerifyErr {
					t.Fatalf("verification test failed %v", sc.Verify(verifier))
				}
				if _, err := sc.Sign("second", signer, options.WithCryptoSignerOpts(test.opts)); err != nil {
					t.Fatalf("adding second signature failed: %v", err)
				}
				if len(sc.Signatures) != 2 {
					t.Fatalf("expected two signatures on checkpoint, only found %v", len(sc.Signatures))
				}
				// finally, test marshalling object and unmarshalling
				marshalledSc, err := sc.MarshalText()
				if err != nil {
					t.Fatalf("error during marshalling: %v", err)
				}
				text, _ = test.c.MarshalText()
				sc2 := &SignedNote{
					Note: string(text),
				}
				if err := sc2.UnmarshalText(marshalledSc); err != nil {
					t.Fatalf("error unmarshalling just marshalled object %v\n%v", err, string(marshalledSc))
				}
				if diff := cmp.Diff(sc, sc2); len(diff) != 0 {
					t.Fatalf("UnmarshalText = diff %s", diff)
				}
			}
		})
	}
}

func TestInvalidSigVerification(t *testing.T) {
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, test := range []struct {
		checkpoint     Checkpoint
		s              []note.Signature
		pubKey         crypto.PublicKey
		expectedResult bool
	}{
		{
			checkpoint: Checkpoint{
				Ecosystem: "Log Checkpoint v0",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			s:              []note.Signature{},
			pubKey:         ecdsaKey.Public(),
			expectedResult: false,
		},
		{

			checkpoint: Checkpoint{
				Ecosystem: "Log Checkpoint v0 not base64",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			pubKey: ecdsaKey.Public(),
			s: []note.Signature{
				{
					Name:   "something",
					Hash:   1234,
					Base64: "not_base 64 string",
				},
			},
			expectedResult: false,
		},
		{
			checkpoint: Checkpoint{
				Ecosystem: "Log Checkpoint v0 invalid signature",
				Size:      123,
				Hash:      []byte("bananas"),
			},
			pubKey: ecdsaKey.Public(),
			s: []note.Signature{
				{
					Name:   "someone",
					Hash:   142,
					Base64: "bm90IGEgc2ln", // valid base64, not a valid signature
				},
			},
			expectedResult: false,
		},
	} {
		t.Run(string(test.checkpoint.Ecosystem), func(t *testing.T) {
			text, _ := test.checkpoint.MarshalText()
			sc := SignedNote{
				Note:       string(text),
				Signatures: test.s,
			}
			verifier, _ := signature.LoadVerifier(test.pubKey, crypto.SHA256)
			result := sc.Verify(verifier)
			if result != test.expectedResult {
				t.Fatal("verification test generated unexpected result")
			}
		})
	}
}

// does not test validity of signatures but merely parsing logic
func TestUnmarshalSignedCheckpoint(t *testing.T) {
	for _, test := range []struct {
		desc    string
		m       string
		wantErr bool
	}{
		{
			desc:    "invalid checkpoint, no signatures",
			m:       "Log Checkpoint v0\n\nYmFuYW5hcw==\n\n",
			wantErr: true,
		}, {
			desc:    "valid checkpoint, no signatures",
			m:       "Log Checkpoint v0\n123\nYmFuYW5hcw==\n\n",
			wantErr: true,
		}, {
			desc:    "incorrect signature line format",
			m:       "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n* name not-a-sig\n",
			wantErr: true,
		}, {
			desc:    "signature not base64 encoded",
			m:       "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 name not-b64\n",
			wantErr: true,
		}, {
			desc:    "missing identity",
			m:       "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 YQ==\n",
			wantErr: true,
		}, {
			desc:    "signature base64 encoded but too short",
			m:       "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 name YQ==\n",
			wantErr: true,
		}, {
			desc:    "valid signed checkpoint - single signature",
			m:       "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n",
			wantErr: false,
		}, {
			desc:    "valid signed checkpoint - two signatures",
			m:       "Banana Checkpoint v1\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n\n\u2014 name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n\u2014 another_name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n",
			wantErr: false,
		},
	} {
		t.Run(string(test.desc), func(t *testing.T) {
			var got SignedNote
			var gotErr error
			if gotErr = got.UnmarshalText([]byte(test.m)); (gotErr != nil) != test.wantErr {
				t.Fatalf("UnmarshalText(%s) = %q, wantErr: %v", test.desc, gotErr, test.wantErr)
			}
			if !test.wantErr != SignedCheckpointValidator(test.m) {
				t.Fatalf("Validator failed for %s", test.desc)
			}
		})
	}
}
