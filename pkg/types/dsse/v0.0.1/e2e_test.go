//
// Copyright 2023 The Sigstore Authors.
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

//go:build e2e

package dsse

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"

	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/util"
)

func rekorServer() string {
	if s := os.Getenv("REKOR_SERVER"); s != "" {
		return s
	}
	return "http://localhost:3000"
}

func GenerateSingleSignedDSSE(t *testing.T) ([]byte, []byte) {
	t.Helper()

	// Get some random data so it's unique each run
	d := util.RandomData(t, 10)
	id := base64.StdEncoding.EncodeToString(d)

	it := in_toto.ProvenanceStatement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: slsa.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "foobar",
					Digest: common.DigestSet{
						"foo": "bar",
					},
				},
			},
		},
		Predicate: slsa.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: "foo" + id,
			},
		},
	}

	b, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}

	pb, _ := pem.Decode([]byte(sigx509.ECDSAPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	s, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := dsse.NewEnvelopeSigner(&sigx509.Verifier{
		S: s,
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := signer.SignPayload(context.Background(), in_toto.PayloadType, b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	return b, eb
}

func GenerateDoubleSignedDSSE(t *testing.T) ([]byte, []byte) {
	t.Helper()

	// Get some random data so it's unique each run
	d := util.RandomData(t, 10)
	id := base64.StdEncoding.EncodeToString(d)

	it := in_toto.ProvenanceStatement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: slsa.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{
				{
					Name: "foobar",
					Digest: common.DigestSet{
						"foo": "bar",
					},
				},
			},
		},
		Predicate: slsa.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: "foo" + id,
			},
		},
	}

	b, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}

	evps := []*sigx509.Verifier{}

	pb, _ := pem.Decode([]byte(sigx509.ECDSAPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signECDSA, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	evps = append(evps, &sigx509.Verifier{
		S: signECDSA,
	})

	pbRSA, _ := pem.Decode([]byte(sigx509.RSAKey))
	rsaPriv, err := x509.ParsePKCS8PrivateKey(pbRSA.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signRSA, err := signature.LoadRSAPKCS1v15Signer(rsaPriv.(*rsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	evps = append(evps, &sigx509.Verifier{
		S: signRSA,
	})

	signer, err := dsse.NewMultiEnvelopeSigner(2, evps[0], evps[1])
	if err != nil {
		t.Fatal(err)
	}

	env, err := signer.SignPayload(context.Background(), in_toto.PayloadType, b)
	if err != nil {
		t.Fatal(err)
	}

	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	return b, eb
}

func TestDsse(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	pubKeyPath := filepath.Join(td, "pub.pem")

	b, eb := GenerateSingleSignedDSSE(t)

	util.Write(t, string(eb), attestationPath)
	util.Write(t, sigx509.ECDSAPub, pubKeyPath)

	out := util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "dsse", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "get", "--uuid", uuid, "--format=json")
	g := util.GetOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	// The attestation should not be stored

	if len(g.Attestation) > 0 {
		t.Fatal("unexpected attestation present in response")
	}

	payloadHash := sha256.Sum256(b)
	envelopeHash := sha256.Sum256(eb)

	dsseModel := &models.DSSEV001Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["DSSEObj"], dsseModel); err != nil {
		t.Errorf("could not convert body into dsse type: %v", err)
	}
	if dsseModel.PayloadHash == nil {
		t.Errorf("could not find hash over payload %v", dsseModel)
	}
	recordedPayloadHash, err := hex.DecodeString(*dsseModel.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting payload hash to []byte: %v", err)
	}

	if !bytes.Equal(payloadHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("payload hash %v doesnt match the payload we sent %v", hex.EncodeToString(payloadHash[:]),
			*dsseModel.PayloadHash.Value))
	}
	if dsseModel.EnvelopeHash == nil {
		t.Errorf("could not find hash over entire envelope %v", dsseModel)
	}
	recordedEnvelopeHash, err := hex.DecodeString(*dsseModel.EnvelopeHash.Value)
	if err != nil {
		t.Errorf("error converting Envelope hash to []byte: %v", err)
	}

	if !bytes.Equal(envelopeHash[:], recordedEnvelopeHash) {
		t.Fatal(fmt.Errorf("envelope hash %v doesnt match the payload we sent %v", hex.EncodeToString(envelopeHash[:]),
			*dsseModel.EnvelopeHash.Value))
	}

	if len(dsseModel.Signatures) != 1 {
		t.Fatalf("expected one signatures but got %d instead", len(dsseModel.Signatures))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "dsse", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
}
func TestDsseMultiSig(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	ecdsapubKeyPath := filepath.Join(td, "ecdsapub.pem")
	rsapubKeyPath := filepath.Join(td, "rsapub.pem")

	b, eb := GenerateDoubleSignedDSSE(t)

	util.Write(t, string(eb), attestationPath)
	util.Write(t, sigx509.ECDSAPub, ecdsapubKeyPath)
	util.Write(t, sigx509.PubKey, rsapubKeyPath)

	out := util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "dsse", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "get", "--uuid", uuid, "--format=json")
	g := util.GetOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	// The attestation should not be stored

	if len(g.Attestation) > 0 {
		t.Fatal("unexpected attestation present in response")
	}

	payloadHash := sha256.Sum256(b)
	envelopeHash := sha256.Sum256(eb)

	dsseModel := &models.DSSEV001Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["DSSEObj"], dsseModel); err != nil {
		t.Errorf("could not convert body into dsse type: %v", err)
	}
	if dsseModel.PayloadHash == nil {
		t.Errorf("could not find hash over payload %v", dsseModel)
	}
	recordedPayloadHash, err := hex.DecodeString(*dsseModel.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting payload hash to []byte: %v", err)
	}

	if !bytes.Equal(payloadHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("payload hash %v doesnt match the payload we sent %v", hex.EncodeToString(payloadHash[:]),
			*dsseModel.PayloadHash.Value))
	}

	if dsseModel.EnvelopeHash == nil {
		t.Errorf("could not find hash over envelope %v", dsseModel)
	}
	recordedEnvelopeHash, err := hex.DecodeString(*dsseModel.EnvelopeHash.Value)
	if err != nil {
		t.Errorf("error converting envelope hash to []byte: %v", err)
	}

	if !bytes.Equal(envelopeHash[:], recordedEnvelopeHash) {
		t.Fatal(fmt.Errorf("envelope hash %v doesnt match the payload we sent %v", hex.EncodeToString(envelopeHash[:]),
			*dsseModel.EnvelopeHash.Value))
	}

	if len(dsseModel.Signatures) != 2 {
		t.Fatalf("expected two signatures but got %d instead", len(dsseModel.Signatures))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "dsse", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
}

func DecodeV001FromRekorResponse(t *testing.T, resp *entries.CreateLogEntryCreated) *V001Entry {
	t.Helper()

	for _, e := range resp.Payload {
		b, err := base64.StdEncoding.DecodeString(e.Body.(string))
		if err != nil {
			t.Errorf("could not decode body into dsse type: %v", err)
		}

		pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
		if err != nil {
			t.Errorf("could not unmarshal body into dsse type: %v", err)
		}
		eimpl, err := types.UnmarshalEntry(pe)
		if err != nil {
			t.Errorf("could not unmarshal body into dsse v0.0.1 type: %v", err)
		}
		return eimpl.(*V001Entry)
	}
	return nil
}

// TestSendingCanonicalizedDSSE tests uploading a valid canonicalized entry. This should fail because the type requires
// the ProposedContent fields to be submitted on upload, and canonicalized entries will not have those fields persisted.
func TestSendingCanonicalizedDSSE(t *testing.T) {
	b, eb := GenerateSingleSignedDSSE(t)
	sha := sha256.New()
	sha.Write(b)
	payloadHashBytes := sha.Sum(nil)
	payloadHashStr := hex.EncodeToString(payloadHashBytes)
	sha.Reset()
	sha.Write(eb)
	envelopeHashBytes := sha.Sum(nil)
	envelopeHashStr := hex.EncodeToString(envelopeHashBytes)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub)},
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	dsse_entry := entry.(*models.DSSE)
	v001 := dsse_entry.Spec.(models.DSSEV001Schema)
	v001.EnvelopeHash = &models.DSSEV001SchemaEnvelopeHash{
		Algorithm: swag.String("sha256"),
		Value:     swag.String(envelopeHashStr),
	}
	v001.PayloadHash = &models.DSSEV001SchemaPayloadHash{
		Algorithm: swag.String("sha256"),
		Value:     swag.String(payloadHashStr),
	}
	env := &dsse.Envelope{}
	if err := json.Unmarshal([]byte(*v001.ProposedContent.Envelope), env); err != nil {
		t.Fatalf("error extracting DSSE envelope")
	}
	pk := v001.ProposedContent.PublicKeys[0]
	v001.Signatures = []*models.DSSEV001SchemaSignaturesItems0{
		{
			Signature: &env.Signatures[0].Sig,
			PublicKey: &pk,
		},
	}
	// erase proposed content and overwrite previous
	v001.ProposedContent = nil
	dsse_entry.Spec = v001

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(dsse_entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	if _, err = rc.Entries.CreateLogEntry(params); err == nil {
		t.Fatalf("expected error submitting canonicalized entry to rekor")
	}
	e, ok := err.(*entries.CreateLogEntryBadRequest)
	if !ok {
		t.Errorf("unexpected error returned from rekor: %v", err.Error())
	}
	if !strings.Contains(e.Payload.Message, "missing proposed content") {
		t.Errorf("expected error message to include 'missing proposed content': %v", e.Payload.Message)
	}
}

// TestSendingEntryWithClientComputedHashes tests uploading a valid entry with incorrect client-computed digests
// over the entire envelope and payload. The hashes should be computed server side, and the request should be rejected
func TestSendingEntryWithClientComputedHashes(t *testing.T) {
	b, eb := GenerateSingleSignedDSSE(t)
	sha := sha256.New()
	sha.Write(b)
	payloadHashBytes := sha.Sum(nil)
	payloadHashStr := hex.EncodeToString(payloadHashBytes)
	t.Logf(payloadHashStr)
	sha.Reset()
	sha.Write(eb)
	envelopeHashBytes := sha.Sum(nil)
	envelopeHashStr := hex.EncodeToString(envelopeHashBytes)
	t.Logf(envelopeHashStr)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub)},
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	dsse_entry := entry.(*models.DSSE)
	v001 := dsse_entry.Spec.(models.DSSEV001Schema)
	v001.EnvelopeHash = &models.DSSEV001SchemaEnvelopeHash{
		Algorithm: swag.String("sha256"),
		Value:     swag.String("8810ad581e59f2bc3928b261707a71308f7e139eb04820366dc4d5c18d980225"),
	}
	v001.PayloadHash = &models.DSSEV001SchemaPayloadHash{
		Algorithm: swag.String("sha256"),
		Value:     swag.String("8810ad581e59f2bc3928b261707a71308f7e139eb04820366dc4d5c18d980225"),
	}
	dsse_entry.Spec = v001

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(dsse_entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	_, err = rc.Entries.CreateLogEntry(params)
	if err == nil {
		t.Error("expected error uploading bad entry to Rekor")
	}

	e, ok := err.(*entries.CreateLogEntryBadRequest)
	if !ok {
		t.Errorf("unexpected error returned from rekor: %v", err.Error())
	}
	if !strings.Contains(e.Payload.Message, "either proposedContent or envelopeHash, payloadHash, and signatures must be present but not both") {
		t.Errorf("unexpected error message returned: %v", e.Payload.Message)
	}
}

// TestMismatchedKeySingleSigner tests uploading a valid entry with the incorrect public key; this should be rejected by Rekor
func TestMismatchedKeySingleSigner(t *testing.T) {
	_, eb := GenerateSingleSignedDSSE(t)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub)}, // this is the matching key, we will swap it out momentarily
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	// swap out good public key for mismatched one
	dsse_entry := entry.(*models.DSSE)
	v001 := dsse_entry.Spec.(models.DSSEV001Schema)
	v001.ProposedContent.PublicKeys[0] = strfmt.Base64(sigx509.RSACert)
	dsse_entry.Spec = v001

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(dsse_entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	if _, err = rc.Entries.CreateLogEntry(params); err == nil {
		t.Fatalf("expected error submitting canonicalized entry to rekor")
	}
	e, ok := err.(*entries.CreateLogEntryBadRequest)
	if !ok {
		t.Errorf("unexpected error returned from rekor: %v", err.Error())
	}
	if !strings.Contains(e.Payload.Message, "could not verify envelope") {
		t.Errorf("expected error message to include 'could not verify envelope': %v", e.Payload.Message)
	}
}

// TestNoSignature tests sending a valid JSON object as the DSSE envelope, but one that omits the
// signature. This should not be accepted by Rekor.
func TestNoSignature(t *testing.T) {
	_, eb := GenerateSingleSignedDSSE(t)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub)}, //, []byte(sigx509.ECDSAPub)},
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	dsse_entry := entry.(*models.DSSE)
	v001 := dsse_entry.Spec.(models.DSSEV001Schema)

	env := &dsse.Envelope{}
	if err := json.Unmarshal([]byte(*v001.ProposedContent.Envelope), env); err != nil {
		t.Fatalf("error extracting DSSE envelope")
	}

	// remove signature
	env.Signatures = []dsse.Signature{}

	noSigEnv, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("error marshalling sorted DSSE envelope")
	}

	v001.ProposedContent.Envelope = swag.String(string(noSigEnv))
	dsse_entry.Spec = v001

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(dsse_entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	if _, err := rc.Entries.CreateLogEntry(params); err == nil {
		t.Errorf("expected error to be returned from rekor given lack of signature in envelope")
	}
}

// TestTwoPublicKeysOneSignature tests uploading a valid entry with the both the correct and an incorrect public key;
// this should be accepted by Rekor, but with only the key that successfully verifies the signature.
func TestTwoPublicKeysOneSignature(t *testing.T) {
	_, eb := GenerateSingleSignedDSSE(t)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub), []byte(sigx509.ECDSAPub)},
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	resp, err := rc.Entries.CreateLogEntry(params)
	if err != nil {
		t.Errorf("unexpected error returned from rekor: %v", err.Error())
	}

	v001 := DecodeV001FromRekorResponse(t, resp)

	if len(v001.DSSEObj.Signatures) != 1 {
		t.Errorf("incorrect number of signatures returned in response: expected 1, got %d", len(v001.DSSEObj.Signatures))
	}
}

// TestTwoPublicKeysTwoSignatures tests uploading a valid entry with the both the correct and an incorrect public key;
// this should be rejected by Rekor, as both signatures were not successfully verified
func TestTwoPublicKeysTwoSignatures(t *testing.T) {
	_, eb := GenerateDoubleSignedDSSE(t)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub), []byte(sigx509.RSACert)}, // missing RSA pub key
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	// swap out one of the good public keys for a mismatched one
	dsse_entry := entry.(*models.DSSE)
	v001 := dsse_entry.Spec.(models.DSSEV001Schema)
	v001.ProposedContent.PublicKeys[0] = strfmt.Base64(sigx509.RSACert)
	v001.ProposedContent.PublicKeys[1] = strfmt.Base64(sigx509.RSACert)
	dsse_entry.Spec = v001

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(dsse_entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	if _, err := rc.Entries.CreateLogEntry(params); err == nil {
		t.Errorf("expected error to be returned from rekor given incorrect public keys provided")
	}
}

// TestThreePublicKeysTwoSignatures tests uploading a valid entry with the both the correct keys and an additional
// incorrect public key; this should be accepted by Rekor, but with only the two keys that successfully verified the signatures
func TestThreePublicKeysTwoSignatures(t *testing.T) {
	_, eb := GenerateDoubleSignedDSSE(t)

	ap := types.ArtifactProperties{
		ArtifactBytes:  eb,
		PublicKeyBytes: [][]byte{[]byte(sigx509.ECDSAPub), []byte(sigx509.ECDSAPub), []byte(sigx509.RSACert)},
	}

	ei := NewEntry()

	entry, err := ei.CreateFromArtifactProperties(context.Background(), ap)
	if err != nil {
		t.Fatalf("error creating entry: %v", err)
	}

	rc, err := client.GetRekorClient(rekorServer())
	if err != nil {
		t.Errorf("error getting client: %v", err)
	}

	params := &entries.CreateLogEntryParams{}
	params.SetProposedEntry(entry)
	params.SetContext(context.Background())
	params.SetTimeout(5 * time.Second)

	resp, err := rc.Entries.CreateLogEntry(params)
	if err != nil {
		t.Errorf("unexpected error returned from rekor: %v", err.Error())
	}

	for _, k := range resp.Payload {
		b, err := base64.StdEncoding.DecodeString(k.Body.(string))
		if err != nil {
			t.Errorf("unexpected error returned from rekor: %v", err.Error())
		}

		pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
		if err != nil {
			t.Errorf("unexpected error returned from rekor: %v", err.Error())
		}
		eimpl, err := types.UnmarshalEntry(pe)
		if err != nil {
			t.Errorf("unexpected error returned from rekor: %v", err.Error())
		}

		dsse_eimpl := eimpl.(*V001Entry)

		if len(dsse_eimpl.DSSEObj.Signatures) != 2 {
			t.Errorf("incorrect number of signatures returned in response: expected 2, got %d", len(dsse_eimpl.DSSEObj.Signatures))
		}
	}
}
