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

package newentry

import (
	"strings"
	"time"

	"github.com/sigstore/rekor/pkg/events"
	"golang.org/x/exp/slices"

	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

const (
	Name   = "dev.sigstore.rekor.events.v1.NewEntry"
	Source = "/createLogEntry"
)

var ty *events.EventType

func init() {
	empty := &rekor_pb.TransparencyLogEntry{}
	ty = events.RegisterType(Name, Source, empty.ProtoReflect().Descriptor())
}

func New(id string, entry *rekor_pb.TransparencyLogEntry, subjects []string) (*events.Event, error) {
	slices.Sort(subjects) // Must be sorted for consistency.
	attrs := map[string]any{
		"time":                   time.Unix(entry.GetIntegratedTime(), 0),
		"rekor_entry_kind":       entry.GetKindVersion().GetKind(),
		"rekor_signing_subjects": strings.Join(subjects, ","),
	}
	return ty.New(id, entry, attrs)
}
