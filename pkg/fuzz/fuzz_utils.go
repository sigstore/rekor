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

package fuzz

import (
	"net/url"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
)

func CreateProps(ff *fuzz.ConsumeFuzzer) (types.ArtifactProperties, func(), error) {
	props := types.ArtifactProperties{}
	ff.GenerateStruct(&props) //nolint:all

	if props.ArtifactBytes == nil {
		artifactBytes, err := ff.GetBytes()
		if err != nil {
			return props, nil, err
		}
		artifactFile, err := os.Create("ArtifactFile")
		if err != nil {
			return props, nil, err
		}
		defer artifactFile.Close()

		artifactPath, err := filepath.Abs("ArtifactFile")
		if err != nil {
			return props, nil, err
		}
		artifactURL, err := url.Parse(artifactPath)
		if err != nil {
			return props, nil, err
		}
		props.ArtifactPath = artifactURL

		_, err = artifactFile.Write(artifactBytes)
		return props, func() {
			os.Remove("ArtifactFile")
		}, err

	}
	return props, func() {}, nil
}

func SetFuzzLogger() {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	log.Logger = logger.Named("rekor-fuzz-logger").Sugar()
}
