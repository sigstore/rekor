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

// Package events
package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sigstore/protobuf-specs/gen/pb-go/events/v1"
)

// The content type of an event.
type EventContentType string

const (
	ContentTypeProtobuf EventContentType = "application/protobuf"
	ContentTypeJSON     EventContentType = "application/json"
)

// Keys that cannot be used in the optional event attributes map due to
// collisions with mandatory fields in the CloudEvents spec.
var reservedFields = map[string]struct{}{
	"datacontenttype": {},
	"data":            {},
	"id":              {},
	"source":          {},
	"specversion":     {},
	"type":            {},
}

// Event is an instance of a certain event type.
type Event struct {
	ty    *EventType
	id    string
	msg   protoreflect.ProtoMessage
	attrs map[string]any
}

// Type returns the underlying event type.
func (e Event) Type() *EventType {
	return e.ty
}

// ID returns the identifier for the event.
func (e Event) ID() string {
	return e.id
}

// Attributes returns the attributes attached to the event. These attributes
// are optional and this function may return an empty map.
func (e Event) Attributes() map[string]any {
	return e.attrs
}

// Message returns the underlying message (aka data) of the event.
func (e Event) Message() protoreflect.ProtoMessage {
	return e.msg
}

// New creates a new event of a given type.
//
// The "id" and "msg" parameters are required. The "attributes" parameter
// supports the following value types:
//   - string
//   - int
//   - bool
//   - []byte
//   - time.Time
func (t *EventType) New(id string, msg protoreflect.ProtoMessage, attributes map[string]any) (*Event, error) {
	if id == "" {
		return nil, errors.New("id must be set")
	}
	if msg == nil {
		return nil, errors.New("msg must be set")
	}
	ty := msg.ProtoReflect().Descriptor().FullName()
	if tty := t.Descriptor().FullName(); ty != tty {
		return nil, fmt.Errorf("msg type %q does not match expected type %q", ty, tty)
	}

	for name, value := range attributes {
		if _, ok := reservedFields[name]; ok {
			return nil, fmt.Errorf("attribute name %q is one of the reserved CloudEvents names %v", name, reservedFields)
		}
		switch v := value.(type) {
		case string, bool, int, []byte, time.Time:
			// Allowed types are a no-op.
		default:
			return nil, fmt.Errorf("unsupported attribute type for %q: %T", name, v)
		}
	}

	return &Event{ty: t, id: id, msg: msg, attrs: attributes}, nil
}

// MarshalJSON serializes the event to JSON, following the CloudEvents
// specification.
func (e *Event) MarshalJSON() ([]byte, error) {
	data, err := protojson.Marshal(e.msg)
	if err != nil {
		return nil, fmt.Errorf("marshal data to JSON: %w", err)
	}

	event := map[string]any{
		"specversion":     CloudEventsSpecVersion,
		"id":              e.ID(),
		"source":          e.Type().Source(),
		"type":            e.Type().Name(),
		"datacontenttype": ContentTypeJSON,
		"data":            string(data),
	}
	for k, v := range e.attrs {
		event[k] = v
	}

	return json.Marshal(event)
}

// MarshalProto serializes the event to the CloudEvents Protobuf wire format.
func (e *Event) MarshalProto() ([]byte, error) {
	msg, err := e.Proto()
	if err != nil {
		return nil, fmt.Errorf("build proto: %w", err)
	}
	return proto.Marshal(msg)
}

// Proto returns the CloudEvents protobuf for the event.
func (e *Event) Proto() (*pb.CloudEvent, error) {
	data, err := proto.Marshal(e.msg)
	if err != nil {
		return nil, fmt.Errorf("marshal data: %w", err)
	}

	attrs := make(map[string]*pb.CloudEvent_CloudEventAttributeValue)
	for name, value := range e.attrs {
		switch v := value.(type) {
		case string:
			attrs[name] = &pb.CloudEvent_CloudEventAttributeValue{
				Attr: &pb.CloudEvent_CloudEventAttributeValue_CeString{CeString: v},
			}
		case bool:
			attrs[name] = &pb.CloudEvent_CloudEventAttributeValue{
				Attr: &pb.CloudEvent_CloudEventAttributeValue_CeBoolean{CeBoolean: v},
			}
		case int:
			attrs[name] = &pb.CloudEvent_CloudEventAttributeValue{
				Attr: &pb.CloudEvent_CloudEventAttributeValue_CeInteger{CeInteger: int32(v)},
			}
		case time.Time:
			attrs[name] = &pb.CloudEvent_CloudEventAttributeValue{
				Attr: &pb.CloudEvent_CloudEventAttributeValue_CeTimestamp{
					CeTimestamp: timestamppb.New(v),
				},
			}
		case []byte:
			attrs[name] = &pb.CloudEvent_CloudEventAttributeValue{
				Attr: &pb.CloudEvent_CloudEventAttributeValue_CeBytes{CeBytes: v},
			}
		}
	}

	event := &pb.CloudEvent{
		SpecVersion: CloudEventsSpecVersion,
		Id:          e.ID(),
		Source:      e.Type().Source(),
		Type:        e.Type().Name(),
		Attributes:  attrs,
		Data: &pb.CloudEvent_ProtoData{
			ProtoData: &anypb.Any{
				Value:   data,
				TypeUrl: string(e.Type().Descriptor().FullName()),
			},
		},
	}

	return event, nil
}
