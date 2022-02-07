//
// Copyright 2021 The Sigstore Authors.
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

package api

import (
	"github.com/go-openapi/runtime/middleware"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/server"
)

func GetRekorVersionHandler(params server.GetRekorVersionParams) middleware.Responder {
	v := version.GetVersionInfo()
	return server.NewGetRekorVersionOK().WithPayload(&models.RekorVersion{
		Version:   &v.GitVersion,
		Commit:    &v.GitCommit,
		Treestate: &v.GitTreeState,
		Builddate: &v.BuildDate,
	})
}
