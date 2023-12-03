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
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/sigstore/rekor/pkg/events"
	sigpubsub "github.com/sigstore/rekor/pkg/pubsub"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
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
		"pubsub.topics.publish",
	}
)

type Publisher struct {
	client *pubsub.Client
	topic  string
	wg     *sync.WaitGroup
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
		wg:     new(sync.WaitGroup),
	}, nil
}

func (p *Publisher) Publish(ctx context.Context, event *events.Event, encoding events.EventContentType) error {
	p.wg.Add(1)
	defer p.wg.Done()

	var data []byte
	var err error
	switch encoding {
	case events.ContentTypeProtobuf:
		data, err = event.MarshalProto()
	case events.ContentTypeJSON:
		data, err = event.MarshalJSON()
	default:
		err = fmt.Errorf("unsupported encoding: %s", encoding)
	}
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	msg := &pubsub.Message{
		Data:       data,
		Attributes: gcpAttrs(event, encoding),
	}

	// The Publish call does not block.
	res := p.client.Topic(p.topic).Publish(ctx, msg)

	// TODO: Consider making the timeout configurable.
	cctx, cancel := context.WithTimeout(ctx, pubsub.DefaultPublishSettings.Timeout)
	defer cancel()

	// This Get call blocks until a response occurs, or the deadline is reached.
	if _, err := res.Get(cctx); err != nil {
		return fmt.Errorf("publish event %s to topic %q: %w", event.ID(), p.topic, err)
	}
	return nil
}

func (p *Publisher) Close() error {
	p.wg.Wait()
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

// GCP Pub/Sub attributes can be used to filter events server-side, reducing
// the processing for the client and reducing GCP costs for egress fees.
func gcpAttrs(event *events.Event, dataType events.EventContentType) map[string]string {
	attrs := map[string]string{
		"source":          event.Type().Source(),
		"type":            event.Type().Name(),
		"datacontenttype": string(dataType),
	}
	for name, value := range event.Attributes() {
		switch v := value.(type) {
		case string:
			attrs[name] = v
		case time.Time:
			attrs[name] = v.Format(time.RFC3339)
		case []byte:
			attrs[name] = base64.StdEncoding.EncodeToString(v)
		default:
			attrs[name] = fmt.Sprint(v)
		}
	}

	return attrs
}
