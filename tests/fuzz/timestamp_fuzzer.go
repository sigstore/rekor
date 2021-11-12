//go:build gofuzz
// +build gofuzz

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

package fuzz

import (
	"context"
	"fmt"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sigstore/rekor/pkg/api"
)

// FuzzTimeStamp uses go-fuzz fuzz the timestamp
func FuzzTimeStamp(data []byte) int {
	f := fuzz.NewConsumer(data)
	x := pkcs9.TimeStampReq{}
	f.AllowUnexportedFields()
	if err := f.GenerateStruct(&x); err != nil {
		return 0
	}
	result, err := api.RequestFromRekor(context.Background(), x)
	if err != nil {
		if result != nil {
			panic(fmt.Sprintf("result wasn't nil when there was an error %v, %v", err, result))
		}
		return 0
	}
	return 1
}
