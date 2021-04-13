/*
Copyright The Rekor Authors.

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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/pubkey"
)

func GetPublicKeyHandler(params pubkey.GetPublicKeyParams) middleware.Responder {
	b, err := x509.MarshalPKIXPublicKey(api.pubkey)
	if err != nil {
		handleRekorAPIError(params, http.StatusInternalServerError, fmt.Errorf("marshal public key err: %w", err), marshalPublicKeyError)
	}
	key := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
	return pubkey.NewGetPublicKeyOK().WithPayload(string(key))
}
