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

package gitpush

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/gitpush"
)

const (
	APIVERSION = "0.0.1"
	beginpgp   = "-----BEGIN PGP SIGNATURE-----"
	endpgp     = "-----END PGP SIGNATURE-----"
)

func init() {
	if err := gitpush.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	GitpushObj models.GitpushV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() []string {
	h := sha256.New()
	for _, input := range []*string{
		v.GitpushObj.Nonce,
		v.GitpushObj.Protocol,
		v.GitpushObj.Pushee,
		v.GitpushObj.Pusher,
		v.GitpushObj.Signature,
	} {
		h.Write([]byte(*input))
	}
	result := "sha256:" + string(h.Sum([]byte{}))
	return append([]string{}, result)
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	gitpushObj := models.Gitpush{}
	gitpushObj.APIVersion = swag.String(APIVERSION)
	// This seems too simple....
	gitpushObj.Spec = &v.GitpushObj

	bytes, err := json.Marshal(&gitpushObj)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Gitpush)
	if !ok {
		return errors.New("cannot unmarshal non Gitpush v0.0.1 type")
	}

	if err := types.DecodeEntry(it.Spec, &v.GitpushObj); err != nil {
		return err
	}

	if err := v.GitpushObj.Validate(strfmt.Default); err != nil {
		return err
	}

	return v.Validate()
}

func (v *V001Entry) Validate() error {
	// TODO: Validate the following fields
	//			pusher should be a git *indent*
	//			protocol should be valid protocol commands
	// Vaidate certificate version
	if !strings.Contains(*v.GitpushObj.CertificateVersion, "certificate version") {
		return errors.New("certificate version does not contain a version")
	}
	ver := strings.Split(*v.GitpushObj.CertificateVersion, " ")
	if len(ver) != 3 {
		return errors.New("certificate version does not contain a version")
	}
	if ver[2] != "0.1" {
		return errors.New("certificate version contains unsupported version")
	}

	// Validate singature is an armored gnupg signature
	// TODO: simple check to not add more needless deps on /x/crypto
	sig := strings.Split(*v.GitpushObj.Signature, "\n")
	if sig[0] != beginpgp {
		return errors.New("signature is not an openpgp armored signature")
	}
	if sig[len(sig)-1] != endpgp {
		return errors.New("signature is not an openpgp armored signature")
	}

	return nil
}

// Not in use

func (v *V001Entry) Attestation() (string, []byte) {
	return "", nil
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	return nil
}

func (v V001Entry) HasExternalEntities() bool {
	return false
}
