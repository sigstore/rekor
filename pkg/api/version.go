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
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/server"
)

// Base version information.
//
// This is the fallback data used when version information from git is not
// provided via go ldflags (e.g. via Makefile).
var (
	// Output of "git describe". The prerequisite is that the branch should be
	// tagged using the correct versioning strategy.
	GitVersion string = "devel"
	// SHA1 from git, output of $(git rev-parse HEAD)
	GitCommit = "unknown"
	// State of git tree, either "clean" or "dirty"
	GitTreeState = "unknown"
	// Build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
	BuildDate = "unknown"
)

func GetRekorVersionHandler(params server.GetRekorVersionParams) middleware.Responder {
	ver := &models.RekorVersion{
		Version:   &GitVersion,
		Commit:    &GitCommit,
		Treestate: &GitTreeState,
		Builddate: &BuildDate,
	}
	return server.NewGetRekorVersionOK().WithPayload(ver)
}
