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

//go:build e2e

package intoto

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
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
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

func TestIntoto(t *testing.T) {
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

	out := util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "get", "--uuid", uuid, "--format=json")
	g := util.GetOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	// The attestation should be stored at /var/run/attestations/sha256:digest

	got := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal([]byte(g.Attestation), &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(it, got); diff != "" {
		t.Errorf("diff: %s", diff)
	}

	attHash := sha256.Sum256(b)

	intotoModel := &models.IntotoV002Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["IntotoObj"], intotoModel); err != nil {
		t.Errorf("could not convert body into intoto type: %v", err)
	}
	if intotoModel.Content == nil || intotoModel.Content.PayloadHash == nil {
		t.Errorf("could not find hash over attestation %v", intotoModel)
	}
	recordedPayloadHash, err := hex.DecodeString(*intotoModel.Content.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting attestation hash to []byte: %v", err)
	}

	if !bytes.Equal(attHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("attestation hash %v doesnt match the payload we sent %v", hex.EncodeToString(attHash[:]),
			*intotoModel.Content.PayloadHash.Value))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
	// issue1649 check for full UUID in printed Location value from 409 response header
	if len(uuid) != sharding.EntryIDHexStringLen {
		t.Fatal("UUID returned instead of entry ID (includes treeID)")
	}
	util.OutputContains(t, out, uuid)
}

func TestIntotoMultiSig(t *testing.T) {
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

	out := util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	util.OutputContains(t, out, "Created entry at")
	uuid := util.GetUUIDFromUploadOutput(t, out)

	out = util.RunCli(t, "get", "--uuid", uuid, "--format=json")
	g := util.GetOut{}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	// The attestation should be stored at /var/run/attestations/$uuid

	got := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal([]byte(g.Attestation), &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(it, got); diff != "" {
		t.Errorf("diff: %s", diff)
	}

	attHash := sha256.Sum256([]byte(g.Attestation))

	intotoV002Model := &models.IntotoV002Schema{}
	if err := types.DecodeEntry(g.Body.(map[string]interface{})["IntotoObj"], intotoV002Model); err != nil {
		t.Errorf("could not convert body into intoto type: %v", err)
	}
	if intotoV002Model.Content.Hash == nil {
		t.Errorf("could not find hash over attestation %v", intotoV002Model)
	}
	recordedPayloadHash, err := hex.DecodeString(*intotoV002Model.Content.PayloadHash.Value)
	if err != nil {
		t.Errorf("error converting attestation hash to []byte: %v", err)
	}

	if !bytes.Equal(attHash[:], recordedPayloadHash) {
		t.Fatal(fmt.Errorf("attestation hash %v doesnt match the payload we sent %v", hex.EncodeToString(attHash[:]),
			*intotoV002Model.Content.PayloadHash.Value))
	}

	out = util.RunCli(t, "upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", ecdsapubKeyPath, "--public-key", rsapubKeyPath)
	util.OutputContains(t, out, "Entry already exists")
}

func TestValidationSearchIntotoV002MissingEnvelope(t *testing.T) {
	body := `{
		"entries":[
			{
				"kind":"intoto",
				"apiVersion": "0.0.2",
				"spec":{
					"content":{
						"hash":{
							"algorithm":"sha256",
							"value":"782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02"
						},
						"payloadHash":{
							"algorithm":"sha256",
							"value":"ebbfddda6277af199e93c5bb5cf5998a79311de238e49bcc8ac24102698761bb"
						}
					},
					"publicKey":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQWlxZ0F3SUJBZ0lVYWhsOEFRd1lZV05ZbnV6dlFvOEVrN1dMTURvd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ESTJNREV4TnpFM1doY05Nakl3T0RJMk1ERXlOekUzV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVLWmZEQzlpalVyclpBWE9jWFYrQXFHRUlTSlEzVHRqSndJdEEKdTE3Rml2aWpnSk1hYUhGNDcrT3Z2OVR1ekFDQ3lpSUV5UDUyZXI2ZmF5bmZKYVVqOEtPQ0FVa3dnZ0ZGTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVHQldUCkMwdUU3dTRQcURVRjFYV0c0QlVWVUpBd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0pRWURWUjBSQVFIL0JCc3dHWUVYYzJGemIyRnJhWEpoTmpFeE5FQm5iV0ZwYkM1amIyMHdLUVlLS3dZQgpCQUdEdnpBQkFRUWJhSFIwY0hNNkx5OWhZMk52ZFc1MGN5NW5iMjluYkdVdVkyOXRNSUdMQmdvckJnRUVBZFo1CkFnUUNCSDBFZXdCNUFIY0FDR0NTOENoUy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJQUFBR0MKMTdtSmhnQUFCQU1BU0RCR0FpRUFoS09BSkdWVlhCb1cxTDR4alk5eWJWOGZUUXN5TStvUEpIeDk5S29LYUpVQwpJUURCZDllc1Q0Mk1STng3Vm9BM1paKzV4akhNZWR6amVxQ2ZoZTcvd1pxYTlUQUtCZ2dxaGtqT1BRUURBd05vCkFEQmxBakVBcnBkeXlFRjc3b2JyTENMUXpzYmIxM2lsNjd3dzM4Y050amdNQml6Y2VUakRiY2VLeVFSN1RKNHMKZENsclkxY1BBakE4aXB6SUQ4VU1CaGxkSmUvZXJGcGdtN2swNWFic2lPN3V5dVZuS29VNk0rTXJ6VVUrZTlGdwpJRGhCanVRa1dRYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
				}
			}
		]
	}
	`
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d instead: %v", resp.StatusCode, string(c))
	}
}

func TestValidationSearchIntotoV002MissingEnvelopeHash(t *testing.T) {
	body := `{
		"entries":[
			{
				"kind":"intoto",
				"apiVersion": "0.0.2",
				"spec":{
					"content":{
						"envelope":{
							"payloadType":"asd",
							"signatures":[ {} ]
						},
						"payloadHash":{
							"algorithm":"sha256",
							"value":"ebbfddda6277af199e93c5bb5cf5998a79311de238e49bcc8ac24102698761bb"
						}
					},
					"publicKey":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQWlxZ0F3SUJBZ0lVYWhsOEFRd1lZV05ZbnV6dlFvOEVrN1dMTURvd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ESTJNREV4TnpFM1doY05Nakl3T0RJMk1ERXlOekUzV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVLWmZEQzlpalVyclpBWE9jWFYrQXFHRUlTSlEzVHRqSndJdEEKdTE3Rml2aWpnSk1hYUhGNDcrT3Z2OVR1ekFDQ3lpSUV5UDUyZXI2ZmF5bmZKYVVqOEtPQ0FVa3dnZ0ZGTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVHQldUCkMwdUU3dTRQcURVRjFYV0c0QlVWVUpBd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0pRWURWUjBSQVFIL0JCc3dHWUVYYzJGemIyRnJhWEpoTmpFeE5FQm5iV0ZwYkM1amIyMHdLUVlLS3dZQgpCQUdEdnpBQkFRUWJhSFIwY0hNNkx5OWhZMk52ZFc1MGN5NW5iMjluYkdVdVkyOXRNSUdMQmdvckJnRUVBZFo1CkFnUUNCSDBFZXdCNUFIY0FDR0NTOENoUy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJQUFBR0MKMTdtSmhnQUFCQU1BU0RCR0FpRUFoS09BSkdWVlhCb1cxTDR4alk5eWJWOGZUUXN5TStvUEpIeDk5S29LYUpVQwpJUURCZDllc1Q0Mk1STng3Vm9BM1paKzV4akhNZWR6amVxQ2ZoZTcvd1pxYTlUQUtCZ2dxaGtqT1BRUURBd05vCkFEQmxBakVBcnBkeXlFRjc3b2JyTENMUXpzYmIxM2lsNjd3dzM4Y050amdNQml6Y2VUakRiY2VLeVFSN1RKNHMKZENsclkxY1BBakE4aXB6SUQ4VU1CaGxkSmUvZXJGcGdtN2swNWFic2lPN3V5dVZuS29VNk0rTXJ6VVUrZTlGdwpJRGhCanVRa1dRYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
				}
			}
		]
	}
	`
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d instead: %v", resp.StatusCode, string(c))
	}
}

func TestValidationSearchIntotoV002MissingPayloadHash(t *testing.T) {
	body := `{
		"entries":[
			{
				"kind":"intoto",
				"apiVersion": "0.0.2",
				"spec":{
					"content":{
						"envelope":{
							"payloadType":"asd",
							"signatures":[ {} ]
						},
						"hash":{
							"algorithm":"sha256",
							"value":"782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02"
						},
					},
					"publicKey":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQWlxZ0F3SUJBZ0lVYWhsOEFRd1lZV05ZbnV6dlFvOEVrN1dMTURvd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ESTJNREV4TnpFM1doY05Nakl3T0RJMk1ERXlOekUzV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVLWmZEQzlpalVyclpBWE9jWFYrQXFHRUlTSlEzVHRqSndJdEEKdTE3Rml2aWpnSk1hYUhGNDcrT3Z2OVR1ekFDQ3lpSUV5UDUyZXI2ZmF5bmZKYVVqOEtPQ0FVa3dnZ0ZGTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVHQldUCkMwdUU3dTRQcURVRjFYV0c0QlVWVUpBd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0pRWURWUjBSQVFIL0JCc3dHWUVYYzJGemIyRnJhWEpoTmpFeE5FQm5iV0ZwYkM1amIyMHdLUVlLS3dZQgpCQUdEdnpBQkFRUWJhSFIwY0hNNkx5OWhZMk52ZFc1MGN5NW5iMjluYkdVdVkyOXRNSUdMQmdvckJnRUVBZFo1CkFnUUNCSDBFZXdCNUFIY0FDR0NTOENoUy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJQUFBR0MKMTdtSmhnQUFCQU1BU0RCR0FpRUFoS09BSkdWVlhCb1cxTDR4alk5eWJWOGZUUXN5TStvUEpIeDk5S29LYUpVQwpJUURCZDllc1Q0Mk1STng3Vm9BM1paKzV4akhNZWR6amVxQ2ZoZTcvd1pxYTlUQUtCZ2dxaGtqT1BRUURBd05vCkFEQmxBakVBcnBkeXlFRjc3b2JyTENMUXpzYmIxM2lsNjd3dzM4Y050amdNQml6Y2VUakRiY2VLeVFSN1RKNHMKZENsclkxY1BBakE4aXB6SUQ4VU1CaGxkSmUvZXJGcGdtN2swNWFic2lPN3V5dVZuS29VNk0rTXJ6VVUrZTlGdwpJRGhCanVRa1dRYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
				}
			}
		]
	}
	`
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 400 {
		t.Fatalf("expected status 400, got %d instead: %v", resp.StatusCode, string(c))
	}
}

func TestValidationSearchIntotoV001MissingPayloadHash(t *testing.T) {
	body := `{
		"entries":[
			{
				"kind":"intoto",
				"apiVersion": "0.0.1",
				"spec":{
					"content":{
						"hash":{
							"algorithm":"sha256",
							"value":"ebbfddda6277af199e93c5bb5cf5998a79311de238e49bcc8ac24102698761bb"
						}
					},
					"publicKey":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQWlxZ0F3SUJBZ0lVYWhsOEFRd1lZV05ZbnV6dlFvOEVrN1dMTURvd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ESTJNREV4TnpFM1doY05Nakl3T0RJMk1ERXlOekUzV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVLWmZEQzlpalVyclpBWE9jWFYrQXFHRUlTSlEzVHRqSndJdEEKdTE3Rml2aWpnSk1hYUhGNDcrT3Z2OVR1ekFDQ3lpSUV5UDUyZXI2ZmF5bmZKYVVqOEtPQ0FVa3dnZ0ZGTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVHQldUCkMwdUU3dTRQcURVRjFYV0c0QlVWVUpBd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0pRWURWUjBSQVFIL0JCc3dHWUVYYzJGemIyRnJhWEpoTmpFeE5FQm5iV0ZwYkM1amIyMHdLUVlLS3dZQgpCQUdEdnpBQkFRUWJhSFIwY0hNNkx5OWhZMk52ZFc1MGN5NW5iMjluYkdVdVkyOXRNSUdMQmdvckJnRUVBZFo1CkFnUUNCSDBFZXdCNUFIY0FDR0NTOENoUy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJQUFBR0MKMTdtSmhnQUFCQU1BU0RCR0FpRUFoS09BSkdWVlhCb1cxTDR4alk5eWJWOGZUUXN5TStvUEpIeDk5S29LYUpVQwpJUURCZDllc1Q0Mk1STng3Vm9BM1paKzV4akhNZWR6amVxQ2ZoZTcvd1pxYTlUQUtCZ2dxaGtqT1BRUURBd05vCkFEQmxBakVBcnBkeXlFRjc3b2JyTENMUXpzYmIxM2lsNjd3dzM4Y050amdNQml6Y2VUakRiY2VLeVFSN1RKNHMKZENsclkxY1BBakE4aXB6SUQ4VU1CaGxkSmUvZXJGcGdtN2swNWFic2lPN3V5dVZuS29VNk0rTXJ6VVUrZTlGdwpJRGhCanVRa1dRYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
				}
			}
		]
	}
	`
	resp, err := http.Post(fmt.Sprintf("%s/api/v1/log/entries/retrieve", rekorServer()),
		"application/json",
		bytes.NewBuffer([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ioutil.ReadAll(resp.Body)
	// No failure when payload hash is not present for canonicalization
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d instead: %v", resp.StatusCode, string(c))
	}
}
