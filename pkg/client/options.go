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

package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"
)

// Option is a functional option for customizing static signatures.
type Option func(*options)

type options struct {
	UserAgent           string
	RetryCount          uint
	RetryWaitMin        time.Duration
	RetryWaitMax        time.Duration
	InsecureTLS         bool
	NoDisableKeepalives bool
	Headers             map[string][]string
}

const (
	// DefaultRetryCount is the default number of retries.
	DefaultRetryCount = 3
)

func makeOptions(opts ...Option) *options {
	o := &options{
		UserAgent:  "",
		RetryCount: DefaultRetryCount,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// WithUserAgent sets the media type of the signature.
func WithUserAgent(userAgent string) Option {
	return func(o *options) {
		o.UserAgent = userAgent
	}
}

// WithRetryCount sets the number of retries.
func WithRetryCount(retryCount uint) Option {
	return func(o *options) {
		o.RetryCount = retryCount
	}
}

// WithRetryWaitMin sets the minimum length of time to wait between retries.
func WithRetryWaitMin(t time.Duration) Option {
	return func(o *options) {
		o.RetryWaitMin = t
	}
}

// WithRetryWaitMax sets the minimum length of time to wait between retries.
func WithRetryWaitMax(t time.Duration) Option {
	return func(o *options) {
		o.RetryWaitMax = t
	}
}

// WithLogger sets the logger; this method is deprecated and will not take any effect.
func WithLogger(_ interface{}) Option {
	return func(*options) {}
}

// WithInsecureTLS disables TLS verification.
func WithInsecureTLS(enabled bool) Option {
	return func(o *options) {
		o.InsecureTLS = enabled
	}
}

// WithNoDisableKeepalives unsets the default DisableKeepalives setting.
func WithNoDisableKeepalives(noDisableKeepalives bool) Option {
	return func(o *options) {
		o.NoDisableKeepalives = noDisableKeepalives
	}
}

// WithHeaders sets default headers for every client request.
func WithHeaders(h map[string][]string) Option {
	return func(o *options) {
		o.Headers = h
	}
}

type roundTripper struct {
	inner http.RoundTripper
	*options
}

// RoundTrip implements `http.RoundTripper`
func (rt *roundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	req.Header.Set("User-Agent", rt.options.UserAgent)
	for k, v := range rt.options.Headers {
		for _, h := range v {
			req.Header.Add(k, h)
		}
	}

	err = retry.Do(func() (err error) {
		res, err = rt.inner.RoundTrip(req)
		return shouldRetry(res, err)
	},
		retry.Attempts(rt.options.RetryCount),
		retry.Delay(rt.options.RetryWaitMin),
		retry.MaxDelay(rt.options.RetryWaitMax),
		retry.DelayType(retry.BackOffDelay),
	)

	return res, err
}

var tooManyRedirectyRe = regexp.MustCompile(`stopped after \d+ redirects\z`)

func shouldRetry(resp *http.Response, err error) error {
	if err != nil {
		urlErr := &url.Error{}

		// Filter well known URL errors
		if errors.As(err, &urlErr) {
			certVerificationErr := &tls.CertificateVerificationError{}

			if tooManyRedirectyRe.MatchString(urlErr.Error()) ||
				strings.Contains(urlErr.Error(), "unsupported protocol scheme") ||
				strings.Contains(urlErr.Error(), "invalid header") ||
				strings.Contains(urlErr.Error(), "certificate is not trusted") ||
				errors.As(urlErr.Err, &certVerificationErr) {
				return nil
			}
		}

		// Retry any other errror
		return err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("retry %d: %s", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode == 0 || (resp.StatusCode >= 500 &&
		resp.StatusCode != http.StatusNotImplemented) {
		return fmt.Errorf("retry unexpected HTTP status %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}

func wrapRoundTripper(inner http.RoundTripper, o *options) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &roundTripper{
		inner:   inner,
		options: o,
	}
}
