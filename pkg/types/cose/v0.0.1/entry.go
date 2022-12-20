//
// Copyright 2022 The Sigstore Authors.
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

package cose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/viper"
	gocose "github.com/veraison/go-cose"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/cose"
)

const (
	APIVERSION = "0.0.1"
)

const (
	CurveP256 = "P-256"
)

func init() {
	if err := cose.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	CoseObj      models.CoseV001Schema
	keyObj       pki.PublicKey
	sign1Msg     *gocose.Sign1Message
	envelopeHash []byte
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	// We add the key, the hash of the overall cose envelope, and the hash of the payload itself as keys.
	keyObj, err := x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return nil, err
	}

	// 1. Key
	key, err := keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}
	result = append(result, keyObj.Subjects()...)

	// 2. Overall envelope
	result = append(result, formatKey(v.CoseObj.Message))

	// 3. Payload
	if v.sign1Msg != nil {
		result = append(result, formatKey(v.sign1Msg.Payload))
	} else {
		// If no payload exists (it's unpacked in validate() method)
		// return now, as we will not be able to extract any headers
		return result, nil
	}

	// If payload is an in-toto statement, let's grab the subjects.
	if rawContentType, ok := v.sign1Msg.Headers.Protected[gocose.HeaderLabelContentType]; ok {
		contentType, ok := rawContentType.(string)
		// Integers as defined by CoAP content format are valid too,
		// but in-intoto payload type is not defined there, so only
		// proceed if content type is a string.
		// See list of CoAP content formats here:
		// https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats
		if ok && contentType == in_toto.PayloadType {
			stmt, err := getIntotoStatement(v.sign1Msg.Payload)
			if err != nil {
				// ContentType header says intoto statement, but
				// parsing failed, continue with a warning.
				log.Logger.Warnf("Failed to parse intoto statement")
			} else {
				for _, sub := range stmt.Subject {
					for alg, digest := range sub.Digest {
						index := alg + ":" + digest
						result = append(result, index)
					}
				}
			}
		}
	}

	return result, nil
}

func getIntotoStatement(b []byte) (*in_toto.Statement, error) {
	var stmt in_toto.Statement
	if err := json.Unmarshal(b, &stmt); err != nil {
		return nil, err
	}

	return &stmt, nil
}

func formatKey(b []byte) string {
	h := sha256.Sum256(b)
	hash := hex.EncodeToString(h[:])
	return strings.ToLower(fmt.Sprintf("%s:%s", models.CoseV001SchemaDataPayloadHashAlgorithmSha256, hash))
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Cose)
	if !ok {
		return errors.New("cannot unmarshal non Cose v0.0.1 type")
	}

	var err error
	if err := types.DecodeEntry(it.Spec, &v.CoseObj); err != nil {
		return err
	}

	// field validation
	if err := v.CoseObj.Validate(strfmt.Default); err != nil {
		return err
	}

	v.keyObj, err = x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return err
	}

	// Store the envelope hash.
	// The CoseObj.Message is only populated during entry creation.
	// When marshalling from the database (retrieval) the envelope
	// hash must be decoded fromt he stored hex string.
	// The envelope hash is used to create the attestation key during
	// retrieval of a record.
	if len(v.CoseObj.Message) == 0 {
		b, err := hex.DecodeString(*v.CoseObj.Data.EnvelopeHash.Value)
		if err != nil {
			return err
		}
		v.envelopeHash = b
	} else {
		h := sha256.Sum256(v.CoseObj.Message)
		v.envelopeHash = h[:]
	}

	return v.validate()
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if v.keyObj == nil {
		return nil, errors.New("cannot canonicalze empty key")
	}
	pk, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	pkb := strfmt.Base64(pk)

	h := sha256.Sum256([]byte(v.sign1Msg.Payload))

	canonicalEntry := models.CoseV001Schema{
		PublicKey: &pkb,
		Data: &models.CoseV001SchemaData{
			PayloadHash: &models.CoseV001SchemaDataPayloadHash{
				Algorithm: swag.String(models.CoseV001SchemaDataPayloadHashAlgorithmSha256),
				Value:     swag.String(hex.EncodeToString(h[:])),
			},
			EnvelopeHash: &models.CoseV001SchemaDataEnvelopeHash{
				Algorithm: swag.String(models.CoseV001SchemaDataEnvelopeHashAlgorithmSha256),
				Value:     swag.String(hex.EncodeToString(v.envelopeHash)),
			},
		},
	}

	itObj := models.Cose{}
	itObj.APIVersion = swag.String(APIVERSION)
	itObj.Spec = &canonicalEntry

	return json.Marshal(&itObj)
}

// validate performs cross-field validation for fields in object
func (v *V001Entry) validate() error {
	// This also gets called in the CLI, where we won't have this data
	// or during record retrieval (message is the raw COSE object) which
	// is only stored as an attestation.
	if len(v.CoseObj.Message) == 0 {
		return nil
	}

	alg, pk, err := getPublicKey(v.keyObj)
	if err != nil {
		return err
	}

	bv, err := gocose.NewVerifier(alg, pk)
	if err != nil {
		return err
	}
	sign1Msg := gocose.NewSign1Message()
	if err := sign1Msg.UnmarshalCBOR(v.CoseObj.Message); err != nil {
		return err
	}

	if err := sign1Msg.Verify(v.CoseObj.Data.Aad, bv); err != nil {
		return err
	}

	v.sign1Msg = sign1Msg
	return nil
}

func getPublicKey(pk pki.PublicKey) (gocose.Algorithm, crypto.PublicKey, error) {
	invAlg := gocose.Algorithm(0)
	x5pk, ok := pk.(*x509.PublicKey)

	if !ok {
		return invAlg, nil, errors.New("invalid public key type")
	}

	cryptoPub := x5pk.CryptoPubKey()

	var alg gocose.Algorithm
	switch t := cryptoPub.(type) {
	case *rsa.PublicKey:
		alg = gocose.AlgorithmPS256
	case *ecdsa.PublicKey:
		alg = gocose.AlgorithmES256
		if t.Params().Name != CurveP256 {
			return invAlg, nil, fmt.Errorf("unsupported elliptic curve %s",
				t.Params().Name)
		}
	default:
		return invAlg, nil, fmt.Errorf("unsupported algorithm type %T", t)
	}

	return alg, cryptoPub, nil
}

// AttestationKey returns the digest of the COSE envelope that was uploaded,
// to be used to lookup the attestation from storage.
func (v *V001Entry) AttestationKey() string {
	return fmt.Sprintf("%s:%s",
		models.CoseV001SchemaDataEnvelopeHashAlgorithmSha256,
		hex.EncodeToString(v.envelopeHash))
}

// AttestationKeyValue returns both the key and value to be persisted
// into attestation storage
func (v *V001Entry) AttestationKeyValue() (string, []byte) {
	storageSize := len(v.CoseObj.Message)
	if storageSize > viper.GetInt("max_attestation_size") {
		log.Logger.Infof("Skipping attestation storage, size %d is greater than max %d", storageSize, viper.GetInt("max_attestation_size"))
		return "", nil
	}

	return v.AttestationKey(), v.CoseObj.Message
}

func (v V001Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Cose{}
	var err error
	messageBytes := props.ArtifactBytes
	if messageBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("cose envelopes cannot be fetched over HTTP(S)")
		}
		messageBytes, err = os.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}
	publicKeyBytes := props.PublicKeyBytes
	if len(publicKeyBytes) == 0 {
		if len(props.PublicKeyPaths) != 1 {
			return nil, errors.New("only one public key must be provided to verify signature")
		}
		keyBytes, err := os.ReadFile(filepath.Clean(props.PublicKeyPaths[0].Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
		publicKeyBytes = append(publicKeyBytes, keyBytes)
	} else if len(publicKeyBytes) != 1 {
		return nil, errors.New("only one public key must be provided")
	}

	kb := strfmt.Base64(publicKeyBytes[0])
	mb := strfmt.Base64(messageBytes)

	re := V001Entry{
		CoseObj: models.CoseV001Schema{
			Data: &models.CoseV001SchemaData{
				Aad: props.AdditionalAuthenticatedData,
			},
			PublicKey: &kb,
			Message:   mb,
		},
	}

	returnVal.Spec = re.CoseObj
	returnVal.APIVersion = swag.String(re.APIVersion())

	return &returnVal, nil
}

func (v V001Entry) Verifier() (pki.PublicKey, error) {
	if v.CoseObj.PublicKey == nil {
		return nil, errors.New("cose v0.0.1 entry not initialized")
	}
	return x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
}
