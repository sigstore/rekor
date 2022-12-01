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

package intoto

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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/viper"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	APIVERSION = "0.0.3"
)

func init() {
	if err := intoto.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V003Entry struct {
	IntotoObj models.IntotoV003Schema
	env       *dsse.Envelope
}

func (v V003Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V003Entry{}
}

// IndexKeys computes the list of keys that should map back to this entry.
// It should *never* reference v.IntotoObj.ProposedContent as those values would only
// be present at the time of insertion
func (v V003Entry) IndexKeys() ([]string, error) {
	var result []string

	for _, sig := range v.IntotoObj.Signatures {
		keyObj, err := x509.NewPublicKey(bytes.NewReader(*sig.PublicKey))
		if err != nil {
			return result, err
		}

		canonKey, err := keyObj.CanonicalValue()
		if err != nil {
			return result, fmt.Errorf("could not canonicalize key: %w", err)
		}

		keyHash := sha256.Sum256(canonKey)
		result = append(result, "sha256:"+hex.EncodeToString(keyHash[:]))

		result = append(result, keyObj.Subjects()...)
	}

	if v.IntotoObj.PayloadHash != nil {
		payloadHashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.IntotoObj.PayloadHash.Algorithm, *v.IntotoObj.PayloadHash.Value))
		result = append(result, payloadHashKey)
	}

	if v.IntotoObj.EnvelopeHash != nil {
		envelopeHashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.IntotoObj.EnvelopeHash.Algorithm, *v.IntotoObj.EnvelopeHash.Value))
		result = append(result, envelopeHashKey)
	}

	if v.env == nil {
		log.Logger.Info("IntotoObj content or DSSE envelope is nil, returning partial set of keys")
		return result, nil
	}

	switch v.env.PayloadType {
	case in_toto.PayloadType:

		if v.env.Payload == "" {
			log.Logger.Info("IntotoObj DSSE payload is empty")
			return result, nil
		}
		decodedPayload, err := v.env.DecodeB64Payload()
		if err != nil {
			return result, fmt.Errorf("could not decode envelope payload: %w", err)
		}
		statement, err := parseStatement(decodedPayload)
		if err != nil {
			return result, err
		}
		for _, s := range statement.Subject {
			for alg, ds := range s.Digest {
				result = append(result, alg+":"+ds)
			}
		}
		// Not all in-toto statements will contain a SLSA provenance predicate.
		// See https://github.com/in-toto/attestation/blob/main/spec/README.md#predicate
		// for other predicates.
		if predicate, err := parseSlsaPredicate(decodedPayload); err == nil {
			if predicate.Predicate.Materials != nil {
				for _, s := range predicate.Predicate.Materials {
					for alg, ds := range s.Digest {
						result = append(result, alg+":"+ds)
					}
				}
			}
		}
	default:
		log.Logger.Infof("Unknown in_toto DSSE envelope Type: %s", v.env.PayloadType)
	}
	return result, nil
}

func parseStatement(p []byte) (*in_toto.Statement, error) {
	ps := in_toto.Statement{}
	if err := json.Unmarshal(p, &ps); err != nil {
		return nil, err
	}
	return &ps, nil
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

func (v *V003Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Intoto)
	if !ok {
		return errors.New("cannot unmarshal non Intoto v0.0.3 type")
	}

	intotoObj := &models.IntotoV003Schema{}

	if err := types.DecodeEntry(it.Spec, intotoObj); err != nil {
		return err
	}

	// field validation
	if err := intotoObj.Validate(strfmt.Default); err != nil {
		return err
	}

	// either we have just proposed content or the canonicalized fields
	if intotoObj.ProposedContent == nil {
		// then we need canonicalized fields, and all must be present (if present, they would have been validated in the above call to Validate())
		if intotoObj.EnvelopeHash == nil || intotoObj.PayloadHash == nil || len(intotoObj.Signatures) == 0 {
			return errors.New("either proposed content or envelope hash, payload hash, and signatures must be present")
		}
		v.IntotoObj = *intotoObj
		return nil
	}
	// if we're here, then we're trying to propose a new entry so we check to ensure client's aren't setting server-side computed fields
	if intotoObj.EnvelopeHash != nil || intotoObj.PayloadHash != nil || len(intotoObj.Signatures) != 0 {
		return errors.New("either proposedContent or envelope hash, payload hash, and signatures must be present but not both")
	}

	env := &dsse.Envelope{}
	if err := json.Unmarshal([]byte(*intotoObj.ProposedContent.Envelope), env); err != nil {
		return err
	}

	allPubKeyBytes := make([][]byte, 0)
	for _, publicKey := range intotoObj.ProposedContent.PublicKeys {
		allPubKeyBytes = append(allPubKeyBytes, publicKey)
	}

	sigToKeyMap, err := verifyEnvelope(allPubKeyBytes, env)
	if err != nil {
		return err
	}

	// we need to ensure we canonicalize the ordering of signatures
	sortedSigs := make([]string, 0, len(sigToKeyMap))
	for sig := range sigToKeyMap {
		sortedSigs = append(sortedSigs, sig)
	}
	sort.Strings(sortedSigs)

	for _, sig := range sortedSigs {
		key := sigToKeyMap[sig]
		canonicalizedKey, err := key.CanonicalValue()
		if err != nil {
			return err
		}
		b64CanonicalizedKey := strfmt.Base64(canonicalizedKey)

		intotoObj.Signatures = append(intotoObj.Signatures, &models.IntotoV003SchemaSignaturesItems0{
			Signature: &sig,
			PublicKey: &b64CanonicalizedKey,
		})
	}

	decodedPayload, err := env.DecodeB64Payload()
	if err != nil {
		// this shouldn't happen because failure would have occurred in verifyEnvelope call above
		return err
	}

	payloadHash := sha256.Sum256(decodedPayload)
	intotoObj.PayloadHash = &models.IntotoV003SchemaPayloadHash{
		Algorithm: swag.String(models.IntotoV003SchemaPayloadHashAlgorithmSha256),
		Value:     swag.String(hex.EncodeToString(payloadHash[:])),
	}

	envelopeHash := sha256.Sum256([]byte(*intotoObj.ProposedContent.Envelope))
	intotoObj.EnvelopeHash = &models.IntotoV003SchemaEnvelopeHash{
		Algorithm: swag.String(models.IntotoV003SchemaEnvelopeHashAlgorithmSha256),
		Value:     swag.String(hex.EncodeToString(envelopeHash[:])),
	}

	// we've gotten through all processing without error, now update the object we're unmarshalling into
	v.IntotoObj = *intotoObj
	v.env = env

	return nil
}

// Canonicalize returns a JSON representation of the entry to be persisted into the log. This
// will be further canonicalized by JSON Canonicalization Scheme (JCS) before being written.
//
// This function should not use v.IntotoObj.ProposedContent fields as they are client provided and
// should not be trusted; the other fields at the top level are only set server side.
func (v *V003Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	canonicalEntry := models.IntotoV003Schema{
		Signatures:   v.IntotoObj.Signatures,
		EnvelopeHash: v.IntotoObj.EnvelopeHash,
		PayloadHash:  v.IntotoObj.PayloadHash,
	}

	sort.Slice(canonicalEntry.Signatures, func(i, j int) bool {
		return *canonicalEntry.Signatures[i].Signature < *canonicalEntry.Signatures[j].Signature
	})

	itObj := models.Intoto{}
	itObj.APIVersion = swag.String(APIVERSION)
	itObj.Spec = &canonicalEntry

	return json.Marshal(&itObj)
}

// AttestationKey returns the digest of the attestation that was uploaded, to be used to lookup the attestation from storage
func (v *V003Entry) AttestationKey() string {
	if v.IntotoObj.PayloadHash != nil {
		return fmt.Sprintf("%s:%s", *v.IntotoObj.PayloadHash.Algorithm, *v.IntotoObj.PayloadHash.Value)
	}
	return ""
}

// AttestationKeyValue returns both the key and value to be persisted into attestation storage
func (v *V003Entry) AttestationKeyValue() (string, []byte) {
	storageSize := base64.StdEncoding.DecodedLen(len(v.env.Payload))
	if storageSize > viper.GetInt("max_attestation_size") {
		log.Logger.Infof("Skipping attestation storage, size %d is greater than max %d", storageSize, viper.GetInt("max_attestation_size"))
		return "", nil
	}
	if v.env == nil {
		return "", nil
	}
	attBytes, err := v.env.DecodeB64Payload()
	if err != nil {
		log.Logger.Infof("could not decode envelope payload: %w", err)
		return "", nil
	}
	return v.AttestationKey(), attBytes
}

type verifier struct {
	s signature.Signer
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

func (v *verifier) Sign(data []byte) (sig []byte, err error) {
	if v.s == nil {
		return nil, errors.New("nil signer")
	}
	sig, err = v.s.SignMessage(bytes.NewReader(data), options.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (v *verifier) Verify(data, sig []byte) error {
	if v.v == nil {
		return errors.New("nil verifier")
	}
	return v.v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
}

func (v V003Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Intoto{}
	re := V003Entry{
		IntotoObj: models.IntotoV003Schema{
			ProposedContent: &models.IntotoV003SchemaProposedContent{},
		},
	}
	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("intoto envelopes cannot be fetched over HTTP(S)")
		}
		artifactBytes, err = os.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}

	env := &dsse.Envelope{}
	if err := json.Unmarshal(artifactBytes, env); err != nil {
		return nil, fmt.Errorf("payload must be a valid DSSE envelope: %w", err)
	}

	allPubKeyBytes := make([][]byte, 0)
	if len(props.PublicKeyBytes) > 0 {
		allPubKeyBytes = append(allPubKeyBytes, props.PublicKeyBytes...)
	}

	if len(props.PublicKeyPaths) > 0 {
		for _, path := range props.PublicKeyPaths {
			if path.IsAbs() {
				return nil, errors.New("dsse public keys cannot be fetched over HTTP(S)")
			}

			publicKeyBytes, err := os.ReadFile(filepath.Clean(path.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading public key file: %w", err)
			}

			allPubKeyBytes = append(allPubKeyBytes, publicKeyBytes)
		}
	}

	keysBySig, err := verifyEnvelope(allPubKeyBytes, env)
	if err != nil {
		return nil, err
	}
	for _, key := range keysBySig {
		canonicalKey, err := key.CanonicalValue()
		if err != nil {
			return nil, err
		}
		re.IntotoObj.ProposedContent.PublicKeys = append(re.IntotoObj.ProposedContent.PublicKeys, strfmt.Base64(canonicalKey))
	}
	re.IntotoObj.ProposedContent.Envelope = swag.String(string(artifactBytes))

	returnVal.Spec = re.IntotoObj
	returnVal.APIVersion = swag.String(re.APIVersion())

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

		dsseVfr, err := dsse.NewEnvelopeVerifier(&verifier{v: vfr})
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
