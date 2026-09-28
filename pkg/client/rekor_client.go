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
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/httpretry"
)

// maxErrorBodyBytes caps how much of the final response body we embed in
// the error message to avoid flooding terminals with large payloads.
const maxErrorBodyBytes = 512

// retryErrorHandler makes the final error surfaced after retries include the
// underlying cause (transport error or final response status + body snippet).
// See https://github.com/sigstore/rekor/issues/2640.
func retryErrorHandler(resp *http.Response, err error, numTries int) (*http.Response, error) {
	if err != nil {
		return nil, fmt.Errorf("giving up after %d attempt(s): %w", numTries, err)
	}
	if resp != nil {
		defer resp.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		snippet := string(bytes.TrimSpace(body))
		if readErr == nil && snippet != "" {
			return nil, fmt.Errorf("giving up after %d attempt(s): status %d: %s",
				numTries, resp.StatusCode, snippet)
		}
		return nil, fmt.Errorf("giving up after %d attempt(s): status %d",
			numTries, resp.StatusCode)
	}

	return nil, fmt.Errorf("giving up after %d attempt(s)", numTries)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// errorHandlingTransport wraps httpretry.Transport to track the actual number
// of attempts and apply retryErrorHandler on exhausted retries, since httpretry
// lacks a native error handler hook.
type errorHandlingTransport struct {
	base       http.RoundTripper
	maxRetries int
	waitMin    time.Duration
	waitMax    time.Duration
	logger     any
}

func (t *errorHandlingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.logger != nil {
		switch v := t.logger.(type) {
		case leveledLogger:
			v.Debug("performing request", "method", req.Method, "url", req.URL.String())
		case logger:
			v.Printf("[DEBUG] %s %s", req.Method, req.URL.String())
		}
	}

	var attempts int
	rt := &httpretry.Transport{
		Base: roundTripFunc(func(attemptReq *http.Request) (*http.Response, error) {
			attempts++
			resp, err := t.base.RoundTrip(attemptReq)
			if err != nil && t.logger != nil {
				switch v := t.logger.(type) {
				case leveledLogger:
					v.Error("request failed", "error", err, "method", attemptReq.Method, "url", attemptReq.URL.String())
				case logger:
					v.Printf("[ERR] %s %s request failed: %v", attemptReq.Method, attemptReq.URL.String(), err)
				}
			}
			return resp, err
		}),
		MaxRetries: t.maxRetries,
		WaitMin:    t.waitMin,
		WaitMax:    t.waitMax,
		Backoff: func(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration {
			wait := httpretry.DefaultBackoff(waitMin, waitMax, attempt, resp)
			if t.logger != nil {
				desc := fmt.Sprintf("%s %s", req.Method, req.URL.String())
				if resp != nil {
					desc = fmt.Sprintf("%s (status: %d)", desc, resp.StatusCode)
				}
				remain := t.maxRetries - attempt
				switch v := t.logger.(type) {
				case leveledLogger:
					v.Debug("retrying request", "request", desc, "timeout", wait, "remaining", remain)
				case logger:
					v.Printf("[DEBUG] %s: retrying in %s (%d left)", desc, wait, remain)
				}
			}
			return wait
		},
	}

	resp, err := rt.RoundTrip(req)
	if attempts > 0 && httpretry.DefaultRetryPolicy(req, resp, err) {
		return retryErrorHandler(resp, err, attempts)
	}
	return resp, err
}

func GetRekorClient(rekorServerURL string, opts ...Option) (*client.Rekor, error) {
	url, err := url.Parse(rekorServerURL)
	if err != nil {
		return nil, err
	}
	o := makeOptions(opts...)

	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default transport does not implement *http.Transport")
	}
	t := dt.Clone()
	if !o.NoDisableKeepalives {
		// MaxIdleConnsPerHost = -1 must only be set when explicitly disabling
		// keep-alives, because MaxIdleConnsPerHost < 0 disables keep-alives in
		// Go's net/http regardless of the DisableKeepAlives flag.
		t.DisableKeepAlives = true
		t.MaxIdleConnsPerHost = -1
	}
	if o.InsecureTLS {
		/* #nosec G402 */
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else if o.TLSConfig != nil {
		t.TLSClientConfig = o.TLSConfig
	}

	httpClient := &http.Client{
		Transport: createRoundTripper(&errorHandlingTransport{
			base:       t,
			maxRetries: int(o.RetryCount),
			waitMin:    o.RetryWaitMin,
			waitMax:    o.RetryWaitMax,
			logger:     o.Logger,
		}, o),
	}

	// sanitize path
	if url.Path == "" {
		url.Path = client.DefaultBasePath
	}

	rt := httptransport.NewWithClient(url.Host, url.Path, []string{url.Scheme}, httpClient)
	rt.Consumers["application/json"] = runtime.JSONConsumer()
	rt.Consumers["application/x-pem-file"] = runtime.TextConsumer()
	rt.Producers["application/json"] = runtime.JSONProducer()

	registry := strfmt.Default
	registry.Add("signedCheckpoint", &util.SignedNote{}, util.SignedCheckpointValidator)
	return client.New(rt, registry), nil
}
