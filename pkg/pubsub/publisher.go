// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pubsub

import (
	"context"
	"fmt"
	"strings"

	"github.com/sigstore/rekor/pkg/events"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// Publisher provides methods for publishing events to a Pub/Sub topic.
type Publisher interface {
	// Publish publishes a CloudEvent to the configured Pub/Sub topic serialized
	// using the specified encoding type.
	Publish(ctx context.Context, event *events.Event, encoding events.EventContentType) error
	// Close safely closes any active connections.
	Close() error
}

// ProviderNotFoundError indicates that no matching PubSub provider was found.
type ProviderNotFoundError struct {
	ref string
}

func (e *ProviderNotFoundError) Error() string {
	return fmt.Sprintf("no pubsub provider found for key reference: %s", e.ref)
}

// ProviderInit is a function that initializes provider-specific Publisher.
type ProviderInit func(ctx context.Context, topicResourceID string) (Publisher, error)

// AddProvider adds the provider implementation into the local cache
func AddProvider(uri string, init ProviderInit) {
	providersMap[uri] = init
}

var providersMap = map[string]ProviderInit{}

// Get returns a Publisher for the given resource string and hash function.
// If no matching provider is found, Get returns a ProviderNotFoundError. It
// also returns an error if initializing the Publisher fails. If no resource
// is supplied, it returns a nil Publisher and no error.
func Get(ctx context.Context, topicResourceID string) (Publisher, error) {
	for ref, pi := range providersMap {
		if strings.HasPrefix(topicResourceID, ref) {
			return pi(ctx, topicResourceID)
		}
	}
	return nil, &ProviderNotFoundError{ref: topicResourceID}
}

// SupportedProviders returns list of initialized providers
func SupportedProviders() []string {
	names := maps.Keys(providersMap)
	slices.Sort(names)
	return names
}
