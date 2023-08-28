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

package events

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	registeredEventTypes = map[string]*EventType{}
	mu                   sync.Mutex
)

// EventType describes the type of an event.
type EventType struct {
	name   string
	source string
	desc   protoreflect.MessageDescriptor
}

// Name returns the unique name for the event type.
func (t EventType) Name() string {
	return t.name
}

// Source returns the source for the event type.
func (t EventType) Source() string {
	return t.source
}

// Descriptor returns the message descriptor for messages of the event type.
func (t EventType) Descriptor() protoreflect.MessageDescriptor {
	return t.desc
}

// RegisterType registers a new event type. It is intended for use in init()
// functions for each event type. It will panic if errors are encountered.
func RegisterType(name, source string, desc protoreflect.MessageDescriptor) *EventType {
	mu.Lock()
	defer mu.Unlock()

	if name == "" {
		panic("event name must be set")
	}
	if source == "" {
		panic("event source must be set")
	}
	if desc == nil {
		panic("event descriptor must be set")
	}
	if _, ok := registeredEventTypes[name]; ok {
		panic("event has already been registered: " + name)
	}
	ty := &EventType{
		name:   name,
		source: source,
		desc:   desc,
	}
	registeredEventTypes[name] = ty
	return ty
}

// EventNotFoundError indicates that no matching PubSub provider was found.
type EventNotFoundError struct {
	name string
}

func (e *EventNotFoundError) Error() string {
	return fmt.Sprintf("event type not found: %s", e.name)
}

// Get returns an event type by name.
func Get(name string) (*EventType, error) {
	v, ok := registeredEventTypes[name]
	if !ok {
		return nil, &EventNotFoundError{name: name}
	}
	return v, nil
}

// RegisteredTypes returns a map of all registered event types. The key is the
// event type name.
func RegisteredTypes() map[string]*EventType {
	return registeredEventTypes
}
