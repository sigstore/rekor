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

package pgpcompat_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-openapi/runtime"
	"github.com/sassoftware/go-rpmutils"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	rpm "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	dir := os.Getenv("REKOR_PGP_FIXTURES")
	if dir == "" {
		dir = "testdata"
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// These tests use only public APIs and can also run in a separate main module,
// where Rekor's replacements are ignored.
func TestIssue2948Upload(t *testing.T) {
	proposed, err := models.UnmarshalProposedEntry(bytes.NewReader(fixture(t, "issue2948.json")), runtime.JSONConsumer())
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(proposed)
	if err != nil {
		t.Fatal(err)
	}
	spec := entry.(*rekord.V001Entry).RekordObj
	props := types.ArtifactProperties{
		ArtifactBytes:  spec.Data.Content,
		SignatureBytes: *spec.Signature.Content,
		PublicKeyBytes: [][]byte{*spec.Signature.PublicKey.Content},
		PKIFormat:      "pgp",
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(props.PublicKeyBytes[0]))
	if err != nil {
		t.Fatal(err)
	}
	if keyring[0].PrimaryKey.Version != 4 {
		t.Fatal("issue 2948 uses a v4 public key")
	}
	// Captured from the parent revision with the pgpkeys-eu replacement.
	const canonicalHash = "65049a82722dd82727ecaa9a740f775443720a3f3413140520c0d9b47a2ddd35"
	t.Run("server entry", func(t *testing.T) {
		checkEntry(t, proposed, canonicalHash)
	})
	t.Run("client artifact", func(t *testing.T) {
		created, err := (&rekord.V001Entry{}).CreateFromArtifactProperties(context.Background(), props)
		if err != nil {
			t.Fatal(err)
		}
		checkEntry(t, created, canonicalHash)
	})
	t.Run("tampered artifact", func(t *testing.T) {
		bad := props
		bad.ArtifactBytes = append([]byte(nil), props.ArtifactBytes...)
		bad.ArtifactBytes[0] ^= 1
		if _, err := (&rekord.V001Entry{}).CreateFromArtifactProperties(context.Background(), bad); err == nil {
			t.Fatal("accepted a tampered artifact")
		}
	})
}

func TestLegacyRPMUpload(t *testing.T) {
	data, key := fixture(t, "legacy-v3.rpm"), fixture(t, "legacy-v3.key")
	header, err := rpmutils.ReadHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := header.GetBytes(rpmutils.SIG_RSA)
	if err != nil {
		t.Fatal(err)
	}
	op, err := packet.NewOpaqueReader(bytes.NewReader(encoded)).Next()
	if err != nil || op.Tag != 2 || len(op.Contents) == 0 || op.Contents[0] != 3 {
		t.Fatalf("fixture must contain a v3 signature: %v", err)
	}
	props := types.ArtifactProperties{ArtifactBytes: data, PublicKeyBytes: [][]byte{key}, PKIFormat: "pgp"}
	proposed, err := (&rpm.V001Entry{}).CreateFromArtifactProperties(context.Background(), props)
	if err != nil {
		t.Fatal(err)
	}
	// Captured from the parent revision with its fork and the pgp3 build tag.
	checkEntry(t, proposed, "3193abe72b7e1efaf0cd7fc273b9e343252dbe728be907e87016f49e67071417")
	t.Run("tampered payload", func(t *testing.T) {
		bad := props
		bad.ArtifactBytes = append([]byte(nil), data...)
		bad.ArtifactBytes[len(data)-1] ^= 1
		if _, err := (&rpm.V001Entry{}).CreateFromArtifactProperties(context.Background(), bad); err == nil {
			t.Fatal("accepted a tampered RPM payload")
		}
	})
}

func checkEntry(t *testing.T, proposed models.ProposedEntry, canonicalHash string) {
	t.Helper()
	entry, err := types.UnmarshalEntry(proposed)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := entry.Insertable(); !ok || err != nil {
		t.Fatalf("entry is not insertable: %v", err)
	}
	canonical, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(canonical)); got != canonicalHash {
		t.Fatalf("canonical SHA256 = %s, want %s", got, canonicalHash)
	}
	logged, err := models.UnmarshalProposedEntry(bytes.NewReader(canonical), runtime.JSONConsumer())
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := types.UnmarshalEntry(logged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replayed.Verifiers(); err != nil {
		t.Fatalf("reading logged verifier: %v", err)
	}
	if _, err := replayed.ArtifactHash(); err != nil {
		t.Fatalf("reading logged artifact hash: %v", err)
	}
}
