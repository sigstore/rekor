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

package api

import (
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapGRPCToHTTP(t *testing.T) {
	tests := []struct {
		code int
		err  error
		want int
	}{
		{http.StatusOK, status.Error(codes.Canceled, "context canceled"), http.StatusOK},
		{http.StatusInternalServerError, status.Error(codes.Canceled, "context canceled"), 499},
		{http.StatusInternalServerError, status.Error(codes.DeadlineExceeded, "deadline exceeded"), http.StatusGatewayTimeout},
		{http.StatusInternalServerError, status.Error(codes.DataLoss, "dataloss"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		if got := mapGRPCToHTTP(tt.code, tt.err); got != tt.want {
			t.Errorf("mapGRPCToHTTP(%v, %e) = %v, want %v", tt.code, tt.err, got, tt.want)
		}
	}
}
