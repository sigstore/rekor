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
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/mod/sumdb/note"
)

// heavily borrowed from https://github.com/google/trillian-examples/blob/master/formats/log/checkpoint_test.go

func TestMarshalTimestampNote(t *testing.T) {
	certChainURL, err := url.Parse("http://localhost:3000/api/v1/timestamp/certchain")
	if err != nil {
		t.Fatal("error parsing URL")
	}
	location, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal("error loading location")
	}
	someTime := time.Date(2021, 07, 26, 0, 0, 0, 0, location)
	for _, test := range []struct {
		msg  []byte
		t    TimestampNote
		want string
	}{
		{
			msg: []byte("bananas"),
			t: TimestampNote{
				Ecosystem:    "Timestamp Note v0",
				Nonce:        big.NewInt(123).Bytes(),
				Time:         someTime,
				Radius:       123,
				CertChainRef: certChainURL,
			},
			want: "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
		},
		{
			msg: []byte("the view from the tree tops is great!"),
			t: TimestampNote{
				Ecosystem:    "Timestamp Note v1",
				Nonce:        big.NewInt(12345678).Bytes(),
				Time:         someTime,
				Radius:       1,
				CertChainRef: certChainURL,
			},
			want: "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
		}, {
			msg: []byte("bananas"),
			t: TimestampNote{
				Ecosystem:    "Timestamp Note v7",
				Nonce:        big.NewInt(123).Bytes(),
				Time:         someTime,
				Radius:       123,
				CertChainRef: certChainURL,
				OtherContent: []string{"foo", "bar"},
			},
			want: "Timestamp Note v7\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\nfoo\nbar\n",
		},
	} {
		t.Run(string(test.t.Ecosystem), func(t *testing.T) {
			h := sha256.Sum256([]byte(test.msg))
			test.t.MessageImprint = "sha256:" + hex.EncodeToString(h[:])
			got, err := test.t.MarshalText()
			if err != nil {
				t.Fatalf("unexpected error marshalling: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("Marshal = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUnmarshalTimestampNote(t *testing.T) {
	certChainURL, err := url.Parse("http://localhost:3000/api/v1/timestamp/certchain")
	if err != nil {
		t.Fatal("error parsing URL")
	}
	location, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal("error loading location")
	}
	someTime := time.Date(2021, 07, 26, 0, 0, 0, 0, location)
	for _, test := range []struct {
		desc    string
		m       string
		want    TimestampNote
		wantErr bool
	}{
		{
			desc: "valid one",
			m:    "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			want: TimestampNote{
				Ecosystem:      "Timestamp Note v0",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			wantErr: false,
		}, {
			desc: "valid with different ecosystem",
			m:    "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			want: TimestampNote{
				Ecosystem:      "Timestamp Note v1",
				MessageImprint: "sha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e",
				Nonce:          big.NewInt(12345678).Bytes(),
				Time:           someTime,
				Radius:         1,
				CertChainRef:   certChainURL,
			},
		}, {
			desc: "valid with trailing data",
			m:    "Timestamp Note v7\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\nfoo\nbar\n",
			want: TimestampNote{
				Ecosystem:      "Timestamp Note v7",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
				OtherContent:   []string{"foo", "bar"},
			},
		}, {
			desc: "valid with trailing newlines",
			m:    "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n\n\n",
			want: TimestampNote{
				Ecosystem:      "Timestamp Note v1",
				MessageImprint: "sha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e",
				Nonce:          big.NewInt(12345678).Bytes(),
				Time:           someTime,
				Radius:         1,
				CertChainRef:   certChainURL,
			},
		}, {
			desc:    "invalid - insufficient lines",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\n",
			wantErr: true,
		}, {
			desc:    "invalid - empty header",
			m:       "\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			wantErr: true,
		}, {
			desc:    "invalid - missing newline",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain",
			wantErr: true,
		}, {
			desc:    "invalid sha - not a valid sha",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			wantErr: true,
		}, {
			desc:    "invalid base64 - nonce",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\n@\n2021-07-26T00:00:00Z\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			wantErr: true,
		}, {
			desc:    "invalid time",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\nabc\n1\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			wantErr: true,
		}, {
			desc:    "invalid radius - not an int",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\na\nhttp://localhost:3000/api/v1/timestamp/certchain\n",
			wantErr: true,
		},
		{
			desc:    "invalid cert chain - not a url",
			m:       "Timestamp Note v1\nsha256:17fb2e8cbf5f60f881c075b1fd0cad32913f2f08b35053fed1c5a785dff90e8e\nvGFO\n2021-07-26T00:00:00Z\n1\n%gh&%ij\n",
			wantErr: true,
		},
	} {
		t.Run(string(test.desc), func(t *testing.T) {
			var got TimestampNote
			var gotErr error
			if gotErr = got.UnmarshalText([]byte(test.m)); (gotErr != nil) != test.wantErr {
				t.Fatalf("Unmarshal = %q, wantErr: %T", gotErr, test.wantErr)
			}
			if diff := cmp.Diff(test.want, got); len(diff) != 0 {
				t.Fatalf("Unmarshalled TimestampNote with diff %s", diff)
			}
			if !test.wantErr != TimestampNoteValidator(test.m) {
				t.Fatalf("Validator failed for %s", test.desc)
			}
		})
	}
}

func TestSigningRoundtripTimestampNote(t *testing.T) {
	certChainURL, err := url.Parse("http://localhost:3000/api/v1/timestamp/certchain")
	if err != nil {
		t.Fatal("error parsing URL")
	}
	location, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal("error loading location")
	}
	someTime := time.Date(2021, 07, 26, 0, 0, 0, 0, location)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPubKey, edPrivKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		t             TimestampNote
		identity      string
		signer        crypto.Signer
		pubKey        crypto.PublicKey
		opts          crypto.SignerOpts
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note RSA v0",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        rsaKey,
			pubKey:        rsaKey.Public(),
			opts:          &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256},
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note ECDSA v0",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        ecdsaKey,
			pubKey:        ecdsaKey.Public(),
			opts:          nil,
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note ED25519 v0",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        edPrivKey,
			pubKey:        edPubKey,
			opts:          crypto.Hash(0),
			wantSignErr:   false,
			wantVerifyErr: false,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note Mismatch v0",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        edPrivKey,
			pubKey:        ecdsaKey.Public(),
			opts:          crypto.Hash(0),
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note Mismatch v1",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        ecdsaKey,
			pubKey:        rsaKey.Public(),
			opts:          &rsa.PSSOptions{Hash: crypto.SHA256},
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note Mismatch v2",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        edPrivKey,
			pubKey:        rsaKey.Public(),
			opts:          &rsa.PSSOptions{Hash: crypto.SHA256},
			wantSignErr:   false,
			wantVerifyErr: true,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note Mismatch v3",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			identity:      "someone",
			signer:        ecdsaKey,
			pubKey:        edPubKey,
			opts:          nil,
			wantSignErr:   false,
			wantVerifyErr: true,
		},
	} {
		t.Run(string(test.t.Ecosystem), func(t *testing.T) {
			text, _ := test.t.MarshalText()
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
				text, _ = test.t.MarshalText()
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

func TestInvalidSigVerificationTimestampNote(t *testing.T) {
	certChainURL, err := url.Parse("http://localhost:3000/api/v1/timestamp/certchain")
	if err != nil {
		t.Fatal("error parsing URL")
	}
	location, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal("error loading location")
	}
	someTime := time.Date(2021, 07, 26, 0, 0, 0, 0, location)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, test := range []struct {
		t              TimestampNote
		s              []note.Signature
		pubKey         crypto.PublicKey
		expectedResult bool
	}{
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note v0",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
			},
			s:              []note.Signature{},
			pubKey:         ecdsaKey.Public(),
			expectedResult: false,
		},
		{
			t: TimestampNote{
				Ecosystem:      "Timestamp Note v0 - not base 64",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
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
			t: TimestampNote{
				Ecosystem:      "Timestamp Note v0 invalid signature",
				MessageImprint: "sha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904",
				Nonce:          big.NewInt(123).Bytes(),
				Time:           someTime,
				Radius:         123,
				CertChainRef:   certChainURL,
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
		t.Run(string(test.t.Ecosystem), func(t *testing.T) {
			text, _ := test.t.MarshalText()
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
func TestUnmarshalSignedTimestampNote(t *testing.T) {
	for _, test := range []struct {
		desc    string
		m       string
		wantErr bool
	}{
		{
			desc:    "invalid timestamp note, no signatures",
			m:       "Timestamp Note v0\n\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n",
			wantErr: true,
		}, {
			desc:    "valid timestamp note, no signatures",
			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n",
			wantErr: true,
		}, {
			desc:    "incorrect signature line format",
			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n* name not-a-sig\n",
			wantErr: true,
		}, {
			desc: "signature not base64 encoded",

			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n\u2014 name not-b64\n",
			wantErr: true,
		}, {
			desc:    "missing identity",
			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n\u2014 YQ==\n",
			wantErr: true,
		}, {
			desc:    "signature base64 encoded but too short",
			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n\u2014 name YQ==\n",
			wantErr: true,
		}, {
			desc:    "valid signed timestamp note - single signature",
			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n\u2014 name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n",
			wantErr: false,
		}, {
			desc:    "valid signed timestamp note - two signatures",
			m:       "Timestamp Note v0\nsha256:e4ba5cbd251c98e6cd1c23f126a3b81d8d8328abc95387229850952b3ef9f904\new==\n2021-07-26T00:00:00Z\n123\nhttp://localhost:3000/api/v1/timestamp/certchain\n\n\u2014 name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n\u2014 another_name pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==\n",
			wantErr: false,
		},
	} {
		t.Run(string(test.desc), func(t *testing.T) {
			var got SignedNote
			var gotErr error
			if gotErr = got.UnmarshalText([]byte(test.m)); (gotErr != nil) != test.wantErr {
				t.Fatalf("UnmarshalText(%s) = %q, wantErr: %v", test.desc, gotErr, test.wantErr)
			}
			if !test.wantErr != SignedTimestampNoteValidator(test.m) {
				t.Fatalf("Validator failed for %s", test.desc)
			}
		})
	}
}
