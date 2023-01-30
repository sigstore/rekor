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

package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
)

type TlogClient struct {
	Proof   []string
	Root    string
	LogInfo models.LogInfo
}

func (m *TlogClient) GetLogProof(params *tlog.GetLogProofParams, opts ...tlog.ClientOption) (*tlog.GetLogProofOK, error) {
	return &tlog.GetLogProofOK{
		Payload: &models.ConsistencyProof{
			Hashes:   m.Proof,
			RootHash: &m.Root,
		}}, nil
}

func (m *TlogClient) GetLogInfo(params *tlog.GetLogInfoParams, opts ...tlog.ClientOption) (*tlog.GetLogInfoOK, error) {
	return &tlog.GetLogInfoOK{
		Payload: &m.LogInfo,
	}, nil
}

// TODO: Implement mock
func (m *TlogClient) SetTransport(transport runtime.ClientTransport) {
}

func TestConsistency(t *testing.T) {
	root2String := "5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45"
	root2, _ := hex.DecodeString(root2String)
	root1, _ := hex.DecodeString("59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c")
	root0, _ := hex.DecodeString("1a341bc342ff4e567387de9789ab14000b147124317841489172419874198147")
	hashes := []string{"d3be742c8d73e2dd3c5635843e987ad3dfb3837616f412a07bf730c3ad73f5cb"}
	for _, test := range []struct {
		name    string
		oldC    util.Checkpoint
		newC    util.Checkpoint
		Proof   []string
		wantErr bool
	}{
		{
			name: "zero length proof",
			oldC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(2),
				Hash:   root2,
			},
			newC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(2),
				Hash:   root2,
			},
			wantErr: false,
		},
		{
			name: "valid consistency proof",
			oldC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(1),
				Hash:   root1,
			},
			newC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(2),
				Hash:   root2,
			},
			wantErr: false,
		},
		{
			name: "invalid new sth request",
			oldC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(2),
				Hash:   root1,
			},
			newC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(1),
				Hash:   root2,
			},
			wantErr: true,
		},
		{
			name: "invalid consistency proof",
			oldC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(1),
				Hash:   root2,
			},
			newC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(2),
				Hash:   root1,
			},
			wantErr: true,
		},
		{
			name: "invalid consistency - same size",
			oldC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(1),
				Hash:   root1,
			},
			newC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(1),
				Hash:   root2,
			},
			wantErr: true,
		},
		{
			name: "invalid consistency - empty log",
			oldC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(0),
				Hash:   root0,
			},
			newC: util.Checkpoint{
				Origin: "test",
				Size:   uint64(2),
				Hash:   root2,
			},
			wantErr: true,
		},
	} {
		var mClient client.Rekor
		mClient.Tlog = &TlogClient{Proof: hashes, Root: root2String}

		t.Run(string(test.name), func(t *testing.T) {

			ctx := context.Background()
			treeID := "123"
			oldSTH, err := util.CreateSignedCheckpoint(test.oldC)
			if err != nil {
				t.Fatalf("creating old checkpoint")
			}
			newSTH, err := util.CreateSignedCheckpoint(test.newC)
			if err != nil {
				t.Fatalf("creating new checkpoint")
			}

			gotErr := ProveConsistency(ctx, &mClient, oldSTH, newSTH, treeID)

			if (gotErr != nil) != test.wantErr {
				t.Fatalf("ProveConsistency = %t, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}

func TestInclusion(t *testing.T) {
	time := int64(1661794812)
	logID := "1701474e8cb504dbb853a5887bc2cf66936b0f36d2641bfb61f1abae80088e6a"
	for _, test := range []struct {
		name    string
		e       models.LogEntryAnon
		wantErr bool
	}{
		{
			name: "valid inclusion",
			e: models.LogEntryAnon{
				Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19",
				IntegratedTime: &time,
				LogID:          &logID,
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						TreeSize: swag.Int64(int64(2)),
						RootHash: swag.String("5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45"),
						LogIndex: swag.Int64(1),
						Hashes: []string{
							"59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c",
						},
					},
					SignedEntryTimestamp: strfmt.Base64("MEUCIHJj8xP+oPTd4BAXhO2lcbRplnKW2FafMiFo0gIDGUcYAiEA80BJ8QikiupGAv3R3dtSvZ1ICsAOQat10cFKPqBkLBM="),
				},
			},
			wantErr: false,
		},
		{
			name: "invalid inclusion - bad body hash",
			e: models.LogEntryAnon{
				Body:           "ayJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19",
				IntegratedTime: &time,
				LogID:          &logID,
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						TreeSize: swag.Int64(int64(2)),
						RootHash: swag.String("5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45"),
						LogIndex: swag.Int64(1),
						Hashes: []string{
							"59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c",
						},
					},
					SignedEntryTimestamp: strfmt.Base64("MEUCIHJj8xP+oPTd4BAXhO2lcbRplnKW2FafMiFo0gIDGUcYAiEA80BJ8QikiupGAv3R3dtSvZ1ICsAOQat10cFKPqBkLBM="),
				},
			},
			wantErr: true,
		},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			ctx := context.Background()

			gotErr := VerifyInclusion(ctx, &test.e)

			if (gotErr != nil) != test.wantErr {
				t.Fatalf("VerifyInclusion = %t, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}

func TestCheckpoint(t *testing.T) {
	hostname := "rekor.localhost"
	treeID := int64(123)
	rootHash := sha256.Sum256([]byte{1, 2, 3})
	rootHashString := hex.EncodeToString(rootHash[:])
	treeSize := uint64(42)
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("error generating signer: %v", err)
	}
	ctx := context.Background()
	scBytes, err := util.CreateAndSignCheckpoint(ctx, hostname, treeID, &types.LogRootV1{TreeSize: treeSize, RootHash: rootHash[:]}, signer)
	if err != nil {
		t.Fatalf("error creating signed checkpoint: %v", err)
	}

	time := int64(1661794812)
	logID := "1701474e8cb504dbb853a5887bc2cf66936b0f36d2641bfb61f1abae80088e6a"

	for _, test := range []struct {
		name    string
		e       models.LogEntryAnon
		wantErr bool
	}{
		{
			name: "valid checkpoint",
			e: models.LogEntryAnon{
				Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19",
				IntegratedTime: &time,
				LogID:          &logID,
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						TreeSize: swag.Int64(int64(2)),
						RootHash: swag.String(rootHashString),
						LogIndex: swag.Int64(1),
						Hashes: []string{
							"59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c",
						},
						Checkpoint: swag.String(string(scBytes)),
					},
					SignedEntryTimestamp: strfmt.Base64("MEUCIHJj8xP+oPTd4BAXhO2lcbRplnKW2FafMiFo0gIDGUcYAiEA80BJ8QikiupGAv3R3dtSvZ1ICsAOQat10cFKPqBkLBM="),
				},
			},
			wantErr: false,
		},
		{
			name: "root hash mismatch",
			e: models.LogEntryAnon{
				Body:           "ayJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19",
				IntegratedTime: &time,
				LogID:          &logID,
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						TreeSize: swag.Int64(int64(2)),
						RootHash: swag.String("5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45"),
						LogIndex: swag.Int64(1),
						Hashes: []string{
							"59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c",
						},
						Checkpoint: swag.String(string(scBytes)),
					},
					SignedEntryTimestamp: strfmt.Base64("MEUCIHJj8xP+oPTd4BAXhO2lcbRplnKW2FafMiFo0gIDGUcYAiEA80BJ8QikiupGAv3R3dtSvZ1ICsAOQat10cFKPqBkLBM="),
				},
			},
			wantErr: true,
		},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			gotErr := VerifyCheckpointSignature(&test.e, signer)

			if (gotErr != nil) != test.wantErr {
				t.Fatalf("VerifyCheckpointSignature = %t, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}
