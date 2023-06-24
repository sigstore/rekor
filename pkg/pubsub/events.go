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

package pubsub

import (
	"fmt"
	"strings"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/events/v1"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

// Event is any protobuf message that has getters for the required fields for
// a CloudEvent.
type Event interface {
	protoreflect.ProtoMessage

	GetSpecVersion() string
	GetId() string
	GetType() string
	GetSource() string
}

// EventType is the unique name of an event type.
type EventType string

const (
	// NewEntryEvent is an event that is published when a new entry is added to
	// Rekor's transparency log.
	NewEntryEvent EventType = "dev.sigstore.rekor.events.v1.NewEntry"
)

// BuildNewEntryEvent builds a new NewEntry event proto message. It takes the
// unique entry ID, entry model, and slice of subjects that signed the entry
// as arguments.
func BuildNewEntryEvent(entryID string, entry models.LogEntryAnon, subjects []string) (*pb.NewEntry, error) {
	if entryID == "" {
		return nil, fmt.Errorf("entryID parameter must be set")
	}
	slices.Sort(subjects) // Must be sorted for consistency.

	validated, err := tle.GenerateTransparencyLogEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("validate entry: %w", err)
	}
	data, err := tle.MarshalTLEToJSON(validated)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	return &pb.NewEntry{
		Id:        entryID,
		Type:      string(NewEntryEvent),
		Data:      string(data),
		DataType:  "application/json",
		Source:    "/createLogEntry",
		EntryKind: validated.GetKindVersion().GetKind(),
		Subjects:  subjects,
		Time:      &tspb.Timestamp{Seconds: validated.IntegratedTime},
	}, nil
}

// EventAttributes returns the attributes for a given event. The key names
// follow the CloudEvents specification. All Rekor-specific attributes have a
// prefix of "rekor_".
func EventAttributes(event Event) map[string]string {
	// Standard CloudEvents attributes defined in the spec.
	attrs := map[string]string{
		"specversion": event.GetSpecVersion(),
		"id":          event.GetId(),
		"source":      event.GetSource(),
		"type":        event.GetType(),
	}

	// Locate any Rekor-specific attributes.
	fields := event.ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if !strings.HasPrefix(fd.JSONName(), "rekor_") {
			continue
		}
		val := event.ProtoReflect().Get(fd).Interface()
		switch x := val.(type) {
		case string:
			attrs[fd.JSONName()] = x
		case []string:
			attrs[fd.JSONName()] = strings.Join(x, ",")
		default:
			attrs[fd.JSONName()] = fmt.Sprintf("%v", x)
		}
	}

	return attrs
}
