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

package rfc3161

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types/rfc3161"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := rfc3161.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	Rfc3161Obj models.Rfc3161V001Schema
	tsrContent *strfmt.Base64
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func NewEntryFromBytes(timestamp []byte) models.ProposedEntry {
	b64 := strfmt.Base64(timestamp)
	re := V001Entry{
		Rfc3161Obj: models.Rfc3161V001Schema{
			Tsr: &models.Rfc3161V001SchemaTsr{
				Content: &b64,
			},
		},
	}

	return &models.Rfc3161{
		Spec:       re.Rfc3161Obj,
		APIVersion: swag.String(re.APIVersion()),
	}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	str := v.Rfc3161Obj.Tsr.Content.String()
	tb, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(tb)
	hx := hex.EncodeToString(h[:])

	payloadKey := "sha256:" + hx
	result = append(result, payloadKey)

	return result, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	rfc3161Resp, ok := pe.(*models.Rfc3161)
	if !ok {
		return errors.New("cannot unmarshal non Rfc3161 v0.0.1 type")
	}

	if err := types.DecodeEntry(rfc3161Resp.Spec, &v.Rfc3161Obj); err != nil {
		return err
	}

	// field validation
	if err := v.Rfc3161Obj.Validate(strfmt.Default); err != nil {
		return err
	}

	if err := v.validate(); err != nil {
		return err
	}

	v.tsrContent = v.Rfc3161Obj.Tsr.Content

	return nil
}

func (v *V001Entry) Canonicalize(_ context.Context) ([]byte, error) {
	if v.tsrContent == nil {
		return nil, errors.New("tsr content must be set before canonicalizing")
	}
	canonicalEntry := models.Rfc3161V001Schema{
		Tsr: &models.Rfc3161V001SchemaTsr{
			Content: v.tsrContent,
		},
	}

	// wrap in valid object with kind and apiVersion set
	ref3161Obj := models.Rfc3161{}
	ref3161Obj.APIVersion = swag.String(APIVERSION)
	ref3161Obj.Spec = &canonicalEntry

	return json.Marshal(&ref3161Obj)
}

// validate performs cross-field validation for fields in object
func (v V001Entry) validate() error {
	data := v.Rfc3161Obj.Tsr
	if data == nil {
		return errors.New("missing tsr data")
	}

	content := *data.Content
	if len(content) == 0 {
		return errors.New("'content' must be specified for data")
	}

	b, err := base64.StdEncoding.DecodeString(content.String())
	if err != nil {
		return err
	}
	if len(b) > (10 * 1024) {
		return fmt.Errorf("tsr exceeds maximum allowed size (10kB)")
	}
	var tsr pkcs9.TimeStampResp
	_, err = asn1.Unmarshal(b, &tsr)
	if err != nil {
		return err
	}
	if tsr.Status.Status != pkcs9.StatusGranted && tsr.Status.Status != pkcs9.StatusGrantedWithMods {
		return fmt.Errorf("tsr status not granted: %v", tsr.Status.Status)
	}
	if !tsr.TimeStampToken.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return fmt.Errorf("tsr wrong content type: %v", tsr.TimeStampToken.ContentType)
	}
	_, err = tsr.TimeStampToken.Content.Verify(nil, false)
	if err != nil {
		return fmt.Errorf("tsr verification error: %w", err)
	}

	return nil
}

func (v V001Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Rfc3161{}

	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("RFC3161 timestamps cannot be fetched over HTTP(S)")
		}
		artifactBytes, err = os.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading artifact file: %w", err)
		}
	}

	b64 := strfmt.Base64(artifactBytes)
	re := V001Entry{
		Rfc3161Obj: models.Rfc3161V001Schema{
			Tsr: &models.Rfc3161V001SchemaTsr{
				Content: &b64,
			},
		},
	}

	returnVal.Spec = re.Rfc3161Obj
	returnVal.APIVersion = swag.String(re.APIVersion())

	return &returnVal, nil
}

func (v V001Entry) Verifiers() ([]pki.PublicKey, error) {
	return nil, errors.New("Verifiers() does not support rfc3161 entry type")
}

func (v V001Entry) ArtifactHash() (string, error) {
	if v.Rfc3161Obj.Tsr == nil || v.Rfc3161Obj.Tsr.Content == nil {
		return "", errors.New("rfc3161 v0.0.1 entry not initialized")
	}
	tsrDecoded, err := base64.StdEncoding.DecodeString(v.Rfc3161Obj.Tsr.Content.String())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(tsrDecoded)
	return strings.ToLower(fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:]))), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if v.Rfc3161Obj.Tsr == nil {
		return false, errors.New("missing tsr property")
	}

	if v.Rfc3161Obj.Tsr.Content == nil || len(*v.Rfc3161Obj.Tsr.Content) == 0 {
		return false, errors.New("missing tsr content")
	}

	if v.tsrContent == nil || len(*v.tsrContent) == 0 {
		return false, errors.New("timestamp response has not been parsed")
	}

	return true, nil
}
