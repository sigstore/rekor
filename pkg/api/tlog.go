/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package api

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/projectrekor/rekor/pkg/generated/models"
	"google.golang.org/grpc/codes"

	"github.com/go-openapi/runtime/middleware"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/tlog"
)

func GetLogInfoHandler(params tlog.GetLogInfoParams) middleware.Responder {
	httpReq := params.HTTPRequest
	api := apiFromRequest(httpReq)

	resp := api.client.getLatest(0)
	if resp.status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianCommunicationError)
	}
	result := resp.getLatestResult

	// validate result is signed with the key we're aware of
	pub, err := x509.ParsePKIXPublicKey(api.pubkey.Der)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, "")
	}
	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, result.SignedLogRoot)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	treeSize := int64(root.TreeSize)

	logInfo := models.LogInfo{
		RootHash: &hashString,
		TreeSize: &treeSize,
	}
	return tlog.NewGetLogInfoOK().WithPayload(&logInfo)
}

func GetLogProofHandler(params tlog.GetLogProofParams) middleware.Responder {
	httpReq := params.HTTPRequest
	if *params.FirstSize > params.LastSize {
		return handleRekorAPIError(params, http.StatusBadRequest, nil, fmt.Sprintf(firstSizeLessThanLastSize, *params.FirstSize, params.LastSize))
	}
	api := apiFromRequest(httpReq)

	resp := api.client.getConsistencyProof(*params.FirstSize, params.LastSize)
	if resp.status != codes.OK {
		return handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("grpc error: %w", resp.err), trillianCommunicationError)
	}
	result := resp.getConsistencyProofResult

	// validate result is signed with the key we're aware of
	pub, err := x509.ParsePKIXPublicKey(api.pubkey.Der)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, "")
	}
	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, result.SignedLogRoot)
	if err != nil {
		return handleRekorAPIError(params, http.StatusInternalServerError, err, trillianUnexpectedResult)
	}

	hashString := hex.EncodeToString(root.RootHash)
	proofHashes := []string{}

	if proof := result.GetProof(); proof != nil {
		for _, hash := range proof.Hashes {
			proofHashes = append(proofHashes, hex.EncodeToString(hash))
		}
	} else {
		return handleRekorAPIError(params, http.StatusInternalServerError, errors.New("grpc call succeeded but no proof returned"), trillianUnexpectedResult)
	}

	consistencyProof := models.ConsistencyProof{
		RootHash: &hashString,
		Hashes:   proofHashes,
	}
	return tlog.NewGetLogProofOK().WithPayload(&consistencyProof)
}
