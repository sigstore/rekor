//
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

package trillianclient

import (
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// grpcDialIgnores tolerates the transient TCP-dial goroutines that grpc spawns
// while establishing a connection (addrConn.connect -> net dialParallel/dialSerial).
// trillian's testonly.NewMockServer opens an eager grpc.Dial connection whose
// reconnect/dial goroutines can outlive its close by a few milliseconds; they
// always terminate once the dial context is canceled, so they are benign. This
// does not mask a real client leak: a leaked grpc client keeps persistent
// transport goroutines (loopyWriter, http2 reader) alive, which goleak still flags.
var grpcDialIgnores = []goleak.Option{
	goleak.IgnoreAnyFunction("net.(*sysDialer).dialParallel"),
	goleak.IgnoreAnyFunction("net.(*sysDialer).dialSerial"),
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, grpcDialIgnores...)
}

// mkSLR builds a SignedLogRoot with the given tree size and root hash.
func mkSLR(t *testing.T, size uint64, rootHash []byte) *trillian.SignedLogRoot {
	t.Helper()
	lr := &types.LogRootV1{TreeSize: size, RootHash: rootHash}
	b, err := lr.MarshalBinary()
	require.NoError(t, err)
	return &trillian.SignedLogRoot{LogRoot: b}
}

// dialMock dials the given address with insecure credentials and registers a
// cleanup to close the connection when the test ends.
func dialMock(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
