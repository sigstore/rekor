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
