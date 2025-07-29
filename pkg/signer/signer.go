/*
Copyright 2021 The Sigstore Authors.

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

package signer

import (
	"context"
	"crypto"
	"strings"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"golang.org/x/exp/slices"

	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"

	// these are imported to load the providers via init() calls
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

// SigningConfig initializes the signer for a specific shard
type SigningConfig struct {
	SigningSchemeOrKeyPath string `json:"signingSchemeOrKeyPath" yaml:"signingSchemeOrKeyPath"`
	FileSignerPassword     string `json:"fileSignerPassword" yaml:"fileSignerPassword"`
	TinkKEKURI             string `json:"tinkKEKURI" yaml:"tinkKEKURI"`
	TinkKeysetPath         string `json:"tinkKeysetPath" yaml:"tinkKeysetPath"`
	GCPKMSRetries          uint   `json:"gcpkmsRetries" yaml:"gcpkmsRetries"`
	GCPKMSTimeout          uint   `json:"gcpkmsTimeout" yaml:"gcpkmsTimeout"`
}

func (sc SigningConfig) IsUnset() bool {
	return sc.SigningSchemeOrKeyPath == "" && sc.FileSignerPassword == "" &&
		sc.TinkKEKURI == "" && sc.TinkKeysetPath == ""
}

func New(ctx context.Context, signer, pass, tinkKEKURI, tinkKeysetPath string, gcpkmsretries, gcpkmstimeout uint) (signature.Signer, error) {
	switch {
	case slices.ContainsFunc(kms.SupportedProviders(),
		func(s string) bool {
			return strings.HasPrefix(signer, s)
		}):
		opts := make([]signature.RPCOption, 0)
		if strings.HasPrefix(signer, gcp.ReferenceScheme) {
			callOpts := []grpc_retry.CallOption{grpc_retry.WithMax(gcpkmsretries), grpc_retry.WithPerRetryTimeout(time.Duration(gcpkmstimeout) * time.Second)}
			opts = append(opts, gcp.WithGoogleAPIClientOption(option.WithGRPCDialOption(grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(callOpts...)))))
		}
		return kms.Get(ctx, signer, crypto.SHA256, opts...)
	case signer == MemoryScheme:
		return NewMemory()
	case signer == TinkScheme:
		return NewTinkSigner(ctx, tinkKEKURI, tinkKeysetPath)
	default:
		return NewFile(signer, pass)
	}
}
