// Copyright 2026 The Sigstore Authors.
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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// logger interface allows to use other loggers than standard log.Logger.
type logger interface {
	Printf(string, ...any)
}

// leveledLogger is an interface that can be implemented by any logger or a
// logger wrapper to provide leveled logging.
type leveledLogger interface {
	Error(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
}

// retryTransport is an http.RoundTripper that retries requests based on policy.
type retryTransport struct {
	Transport    http.RoundTripper
	MaxRetries   uint
	RetryWaitMin time.Duration
	RetryWaitMax time.Duration
	Logger       any
	ErrorHandler func(resp *http.Response, err error, numTries uint) (*http.Response, error)
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	var bodyBytes []byte

	if t.Logger != nil {
		switch v := t.Logger.(type) {
		case leveledLogger:
			v.Debug("performing request", "method", req.Method, "url", req.URL.String())
		case logger:
			v.Printf("[DEBUG] %s %s", req.Method, req.URL.String())
		}
	}

	if req.Body != nil {
		defer req.Body.Close()
		// Clone the request to avoid modifying the original request's Body or GetBody,
		// which would violate the http.RoundTripper contract.
		cloneReq := req.Clone(req.Context())
		if req.GetBody == nil {
			// Read the body so we can replay it
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			cloneReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		cloneReq.Body, err = cloneReq.GetBody()
		if err != nil {
			return nil, err
		}
		req = cloneReq
	}

	for i := uint(0); i <= t.MaxRetries; i++ {
		if err := req.Context().Err(); err != nil {
			if i == 0 && req.Body != nil {
				req.Body.Close()
			}
			return nil, err
		}

		if i > 0 {
			wait := t.RetryWaitMin
			if wait == 0 {
				wait = 1 * time.Second // Default
			}
			waitMax := t.RetryWaitMax
			if waitMax == 0 {
				waitMax = 10 * time.Second // Default max
			}

			// Exponential backoff
			backoff := float64(wait) * math.Pow(2, float64(i-1))
			if backoff > float64(waitMax) {
				backoff = float64(waitMax)
			}
			// Add jitter (between 0.8 and 1.0 of the backoff) to avoid thundering herd.
			//nolint:gosec // cryptographic randomness is not required for retry jitter
			jitter := (rand.Float64() * 0.2) + 0.8
			wait = time.Duration(backoff * jitter)

			if resp != nil {
				if retryAfterStr := resp.Header.Get("Retry-After"); retryAfterStr != "" {
					if sleepSec, err := strconv.ParseInt(retryAfterStr, 10, 64); err == nil {
						headerWait := time.Duration(sleepSec) * time.Second
						if headerWait > wait {
							wait = headerWait
						}
					} else if parsedDate, err := http.ParseTime(retryAfterStr); err == nil {
						headerWait := time.Until(parsedDate)
						if headerWait > wait {
							wait = headerWait
						}
					}
				}
			}

			if wait > waitMax {
				wait = waitMax
			}

			remain := t.MaxRetries - i + 1
			if t.Logger != nil {
				desc := fmt.Sprintf("%s %s", req.Method, req.URL.String())
				if resp != nil {
					desc = fmt.Sprintf("%s (status: %d)", desc, resp.StatusCode)
				}
				switch v := t.Logger.(type) {
				case leveledLogger:
					v.Debug("retrying request", "request", desc, "timeout", wait, "remaining", remain)
				case logger:
					v.Printf("[DEBUG] %s: retrying in %s (%d left)", desc, wait, remain)
				}
			}

			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			}

			if req.GetBody != nil {
				var getErr error
				req.Body, getErr = req.GetBody()
				if getErr != nil {
					return nil, getErr
				}
			}
		}

		transport := t.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		resp, err = transport.RoundTrip(req)

		if err != nil {
			if t.Logger != nil {
				switch v := t.Logger.(type) {
				case leveledLogger:
					if i < t.MaxRetries {
						v.Debug("request failed", "error", err, "method", req.Method, "url", req.URL.String())
					} else {
						v.Error("request failed", "error", err, "method", req.Method, "url", req.URL.String())
					}
				case logger:
					if i < t.MaxRetries {
						v.Printf("[DEBUG] %s %s request failed: %v", req.Method, req.URL.String(), err)
					} else {
						v.Printf("[ERR] %s %s request failed: %v", req.Method, req.URL.String(), err)
					}
				}
			}
			// If context is canceled, exit immediately instead of exhausting retries
			if req.Context().Err() != nil {
				return nil, err
			}
			if !isRecoverableError(err) {
				return nil, err
			}
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented) {
			// Recoverable error
			// Close body before next retry
			if i < t.MaxRetries {
				_, _ = io.CopyN(io.Discard, resp.Body, 4096)
				resp.Body.Close()
				continue
			}
			break
		}

		return resp, err
	}

	if t.ErrorHandler != nil {
		newResp, newErr := t.ErrorHandler(resp, err, t.MaxRetries+1)
		if newResp != resp && resp != nil {
			_, _ = io.CopyN(io.Discard, resp.Body, 4096)
			resp.Body.Close()
		}
		return newResp, newErr
	}
	return resp, err
}

func isRecoverableError(err error) bool {
	if err == nil {
		return true
	}

	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return false
	}
	var unkAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unkAuthErr) {
		return false
	}
	var invCertErr x509.CertificateInvalidError
	if errors.As(err, &invCertErr) {
		return false
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return false
	}

	// Unsupported protocol scheme
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		return false
	}
	return true
}
