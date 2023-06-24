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

// Package gcp implements the pubsub.Publisher with Google Cloud Pub/Sub.
package gcp

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"cloud.google.com/go/pubsub"
	sigpubsub "github.com/sigstore/rekor/pkg/pubsub"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
)

func init() {
	sigpubsub.AddProvider(URIIdentifier, func(ctx context.Context, topicResourceID string) (sigpubsub.Publisher, error) {
		return New(ctx, topicResourceID)
	})
}

const URIIdentifier = "gcppubsub://"

var (
	// Copied from https://github.com/google/go-cloud/blob/master/pubsub/gcppubsub/gcppubsub.go
	re = regexp.MustCompile(`^gcppubsub://projects/([^/]+)/topics/([^/]+)$`)
	// Minimal set of permissions needed to check if the server can publish to the configured topic.
	// https://cloud.google.com/pubsub/docs/access-control#required_permissions
	requiredIAMPermissions = []string{
		"pubsub.topics.get",
		"pubsub.topics.publish",
	}
)

type Publisher struct {
	client *pubsub.Client
	topic  string
}

func New(ctx context.Context, topicResourceID string, opts ...option.ClientOption) (*Publisher, error) {
	projectID, topic, err := parseRef(topicResourceID)
	if err != nil {
		return nil, fmt.Errorf("parse ref: %w", err)
	}
	client, err := pubsub.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, fmt.Errorf("create pubsub client for project %q: %w", projectID, err)
	}

	// The PubSub emulator does not support IAM methods, and will block the
	// server start up if they are called. If the environment variable is set,
	// skip this check.
	if os.Getenv("PUBSUB_EMULATOR_HOST") == "" {
		if _, err := client.Topic(topic).IAM().TestPermissions(ctx, requiredIAMPermissions); err != nil {
			return nil, fmt.Errorf("insufficient permissions for topic %q: %w", topic, err)
		}
	}

	return &Publisher{
		client: client,
		topic:  topic,
	}, nil
}

func (p *Publisher) Publish(ctx context.Context, event sigpubsub.Event) error {
	data, err := protojson.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	msg := &pubsub.Message{
		Data:       data,
		Attributes: sigpubsub.EventAttributes(event),
	}
	res := p.client.Topic(p.topic).Publish(ctx, msg)
	// TODO: Consider making the timeout configurable.
	withTimeout, cancel := context.WithTimeout(ctx, pubsub.DefaultPublishSettings.Timeout)
	defer cancel()
	if _, err := res.Get(withTimeout); err != nil {
		return fmt.Errorf("publish event %q of type %q to topic %q: %w", event.GetId(), event.GetType(), p.topic, err)
	}
	return nil
}

func (p *Publisher) Close() error {
	return p.client.Close()
}

func parseRef(ref string) (projectID, topic string, err error) {
	v := re.FindStringSubmatch(ref)
	if len(v) != 3 {
		err = fmt.Errorf("invalid gcppubsub format %q", ref)
		return
	}
	projectID, topic = v[1], v[2]
	return
}
