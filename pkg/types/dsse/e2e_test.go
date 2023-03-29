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
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
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

func TestDsse(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	pubKeyPath := filepath.Join(td, "pub.pem")

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

	attHash := sha256.Sum256(b)

	dsseModel := &models.DSSEV001Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["DSSEObj"], dsseModel); err != nil {
		t.Errorf("could not convert body into dsse type: %v", err)
	}
	if dsseModel.PayloadHash == nil {
		t.Errorf("could not find hash over attestation %v", dsseModel)
	}
	recordedPayloadHash, err := hex.DecodeString(*dsseModel.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting attestation hash to []byte: %v", err)
	}

	if !bytes.Equal(attHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("attestation hash %v doesnt match the payload we sent %v", hex.EncodeToString(attHash[:]),
			*dsseModel.PayloadHash.Value))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "dsse", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
}
func TestDsseMultiSig(t *testing.T) {
	td := t.TempDir()
	attestationPath := filepath.Join(td, "attestation.json")
	ecdsapubKeyPath := filepath.Join(td, "ecdsapub.pem")
	rsapubKeyPath := filepath.Join(td, "rsapub.pem")

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

	attHash := sha256.Sum256(b)

	dsseModel := &models.DSSEV001Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["DSSEObj"], dsseModel); err != nil {
		t.Errorf("could not convert body into dsse type: %v", err)
	}
	if dsseModel.PayloadHash == nil {
		t.Errorf("could not find hash over attestation %v", dsseModel)
	}
	recordedPayloadHash, err := hex.DecodeString(*dsseModel.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting attestation hash to []byte: %v", err)
	}

	if !bytes.Equal(attHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("attestation hash %v doesnt match the payload we sent %v", hex.EncodeToString(attHash[:]),
			*dsseModel.PayloadHash.Value))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "dsse", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
}
