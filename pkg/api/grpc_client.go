package api

import (
	"context"
	"time"

	"github.com/projectrekor/rekor/pkg/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func dial(ctx context.Context, rpcServer string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Set up and test connection to rpc server
	conn, err := grpc.DialContext(ctx, rpcServer, grpc.WithInsecure())
	if err != nil {
		log.Logger.Fatalf("Failed to connect to RPC server:", err)
	}
	return conn, nil
}

func getGrpcCode(state codes.Code) string {
	// more entries available here: https://github.com/grpc/grpc-go/blob/e6c98a478e62a717b945eb60edb115faf65215d3/codes/codes.go#L198
	var codeResponse string
	switch state {
	case codes.OK:
		codeResponse = "OK"
	case codes.NotFound:
		codeResponse = "Entry not Found"
	case codes.AlreadyExists:
		codeResponse = "Data Already Exists"
	default:
		codeResponse = "Error. Unknown Code!"
	}
	return codeResponse
}
