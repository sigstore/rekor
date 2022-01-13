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

package dsse

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/viper"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := rekordsse.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	DsseObj models.DsseV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string
	fmt.Printf("%+v\n", v.DsseObj)
	result = append(result, v.DsseObj.PayloadHash.Algorithm+":"+v.DsseObj.PayloadHash.Value)

	for _, sig := range v.DsseObj.Signatures {
		keyHash := sha256.Sum256(sig.PublicKey)
		result = append(result, "sha256:"+hex.EncodeToString(keyHash[:]))
	}

	switch *v.DsseObj.PayloadType {
	case in_toto.PayloadType:
		statement, err := parseIntotoStatement(v.DsseObj.Payload)
		if err != nil {
			return result, err
		}

		for _, s := range statement.Subject {
			for alg, ds := range s.Digest {
				result = append(result, alg+":"+ds)
			}
		}
	default:
		log.Logger.Infof("Cannot index payload of type: %s", *v.DsseObj.PayloadType)
	}

	return result, nil
}

func parseIntotoStatement(p []byte) (*in_toto.Statement, error) {
	ps := in_toto.Statement{}
	if err := json.Unmarshal(p, &ps); err != nil {
		return nil, err
	}

	return &ps, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	dsseModel, ok := pe.(*models.Dsse)
	if !ok {
		return errors.New("cannot unmarshal non DSSE v0.0.1 type")
	}

	if err := types.DecodeEntry(dsseModel.Spec, &v.DsseObj); err != nil {
		return err
	}

	// field validation
	if err := v.DsseObj.Validate(strfmt.Default); err != nil {
		return err
	}

	if string(v.DsseObj.Payload) == "" {
		return nil
	}

	env := &dsse.Envelope{
		Payload:     string(v.DsseObj.Payload),
		PayloadType: *v.DsseObj.PayloadType,
	}

	allPubKeyBytes := make([][]byte, 0)
	for _, sig := range v.DsseObj.Signatures {
		env.Signatures = append(env.Signatures, dsse.Signature{
			KeyID: sig.Keyid,
			Sig:   string(sig.Sig),
		})

		allPubKeyBytes = append(allPubKeyBytes, sig.PublicKey)
	}

	if _, err := verifyEnvelope(allPubKeyBytes, env); err != nil {
		return err
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(string(v.DsseObj.Payload))
	if err != nil {
		return fmt.Errorf("could not decode envelope payload: %w", err)
	}

	paeEncodedPayload := dsse.PAE(*v.DsseObj.PayloadType, decodedPayload)
	h := sha256.Sum256(paeEncodedPayload)
	v.DsseObj.PayloadHash = &models.DsseV001SchemaPayloadHash{
		Algorithm: models.DsseV001SchemaPayloadHashAlgorithmSha256,
		Value:     hex.EncodeToString(h[:]),
	}

	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	canonicalEntry := models.DsseV001Schema{
		PayloadHash: v.DsseObj.PayloadHash,
		Signatures:  v.DsseObj.Signatures,
		PayloadType: v.DsseObj.PayloadType,
	}

	model := models.Dsse{}
	model.APIVersion = swag.String(APIVERSION)
	model.Spec = canonicalEntry
	return json.Marshal(&model)
}

func (v *V001Entry) AttestationKey() string {
	if v.DsseObj.PayloadHash != nil {
		return fmt.Sprintf("%s:%s", v.DsseObj.PayloadHash.Algorithm, v.DsseObj.PayloadHash.Value)
	}

	return ""
}

func (v *V001Entry) AttestationKeyValue() (string, []byte) {
	storageSize := base64.StdEncoding.DecodedLen(len(v.DsseObj.Payload))
	if storageSize > viper.GetInt("max_attestation_size") {
		log.Logger.Infof("Skipping attestation storage, size %d is greater than max %d", storageSize, viper.GetInt("max_attestation_size"))
		return "", nil
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(string(v.DsseObj.Payload))
	if err != nil {
		log.Logger.Infof("Skipping attestation storage, error while decoding attestation: %v", err)
		return "", nil
	}

	return v.AttestationKey(), decodedPayload
}

type verifier struct {
	v signature.Verifier
}

func (v *verifier) KeyID() (string, error) {
	return "", nil
}

func (v *verifier) Public() crypto.PublicKey {
	// the dsse library uses this to generate a key ID if the KeyID function returns an empty string
	// as well for the AcceptedKey return value.  Unfortunately since key ids can be arbitrary, we don't
	// know how to generate a matching id for the key id on the envelope's signature...
	// dsse verify will skip verifiers whose key id doesn't match the signature's key id, unless it fails
	// to generate one from the public key... so we trick it by returning nil ¯\_(ツ)_/¯
	return nil
}

func (v *verifier) Verify(data, sig []byte) error {
	if v.v == nil {
		return errors.New("nil verifier")
	}
	return v.v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
}

func (v V001Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Dsse{}
	re := V001Entry{}

	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("dsse envelopes cannot be fetched over HTTP(S)")
		}

		var err error
		artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal(artifactBytes, &env); err != nil {
		return nil, fmt.Errorf("payload must be a valid dsse envelope: %w", err)
	}

	allPubKeyBytes := make([][]byte, 0)
	if props.PublicKeyBytes != nil {
		allPubKeyBytes = append(allPubKeyBytes, props.PublicKeyBytes)
	}

	allPubKeyBytes = append(allPubKeyBytes, props.PublicKeysBytes...)
	allPubKeyPaths := make([]*url.URL, 0)
	if props.PublicKeyPath != nil {
		allPubKeyPaths = append(allPubKeyPaths, props.PublicKeyPath)
	}

	for _, path := range allPubKeyPaths {
		if path.IsAbs() {
			return nil, errors.New("dsse public keys cannot be fetched over HTTP(S)")
		}

		publicKeyBytes, err := ioutil.ReadFile(filepath.Clean(path.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}

		allPubKeyBytes = append(allPubKeyBytes, publicKeyBytes)
	}

	keysBySig, err := verifyEnvelope(allPubKeyBytes, &env)
	if err != nil {
		return nil, err
	}

	re.DsseObj.Payload = strfmt.Base64(env.Payload)
	re.DsseObj.PayloadType = &env.PayloadType
	for _, sig := range env.Signatures {
		key, ok := keysBySig[sig.Sig]
		if !ok {
			return nil, errors.New("all signatures must have a key that verifies it")
		}

		canonKey, err := key.CanonicalValue()
		if err != nil {
			return nil, fmt.Errorf("could not canonicize key: %w", err)
		}

		keyBytes := strfmt.Base64(canonKey)
		re.DsseObj.Signatures = append(re.DsseObj.Signatures, &models.DsseV001SchemaSignaturesItems0{
			Keyid:     sig.KeyID,
			Sig:       sig.Sig,
			PublicKey: keyBytes,
		})
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.DsseObj
	return &returnVal, nil
}

// verifyEnvelope takes in an array of possible key bytes and attempts to parse them as x509 public keys.
// it then uses these to verify the envelope and makes sure that every signature on the envelope is verified.
// it returns a map of verifiers indexed by the signature the verifier corresponds to.
func verifyEnvelope(allPubKeyBytes [][]byte, env *dsse.Envelope) (map[string]*x509.PublicKey, error) {
	// generate a fake id for these keys so we can get back to the key bytes and match them to their corresponding signature
	verifierBySig := make(map[string]*x509.PublicKey)
	allSigs := make(map[string]struct{})
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}

	for _, pubKeyBytes := range allPubKeyBytes {
		key, err := x509.NewPublicKey(bytes.NewReader(pubKeyBytes))
		if err != nil {
			return nil, fmt.Errorf("could not parse public key as x509: %w", err)
		}

		vfr, err := signature.LoadVerifier(key.CryptoPubKey(), crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("could not load verifier: %w", err)
		}

		dsseVfr, err := dsse.NewEnvelopeVerifier(&verifier{
			v: vfr,
		})

		if err != nil {
			return nil, fmt.Errorf("could not use public key as a dsse verifier: %w", err)
		}

		accepted, err := dsseVfr.Verify(env)
		if err != nil {
			return nil, fmt.Errorf("could not verify envelope: %w", err)
		}

		for _, accept := range accepted {
			delete(allSigs, accept.Sig.Sig)
			verifierBySig[accept.Sig.Sig] = key
		}
	}

	if len(allSigs) > 0 {
		return nil, errors.New("all signatures must have a key that verifies it")
	}

	return verifierBySig, nil
}
