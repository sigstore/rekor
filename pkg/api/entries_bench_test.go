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

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/google/trillian"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/entries"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type blockingTrillianServer struct {
	trillian.UnimplementedTrillianLogServer
	arrived chan struct{}
	release chan struct{}
}

func (s *blockingTrillianServer) QueueLeaf(_ context.Context, _ *trillian.QueueLeafRequest) (*trillian.QueueLeafResponse, error) {
	s.arrived <- struct{}{}
	<-s.release
	return nil, status.Error(codes.Canceled, "benchmark release")
}

func makeLargeDSSEPayload(t testing.TB, payloadBytes int) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	rawPayload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicate":"` + strings.Repeat("a", payloadBytes) + `"}`)
	b64Payload := base64.StdEncoding.EncodeToString(rawPayload)
	payloadType := "application/vnd.in-toto+json"

	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(rawPayload), rawPayload)
	digest := sha256.Sum256([]byte(pae))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	env := map[string]any{
		"payloadType": payloadType,
		"payload":     b64Payload,
		"signatures": []map[string]string{
			{"keyid": "", "sig": base64.StdEncoding.EncodeToString(sig)},
		},
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	reqBody := map[string]any{
		"kind":       "dsse",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"proposedContent": map[string]any{
				"envelope":  string(envJSON),
				"verifiers": []string{base64.StdEncoding.EncodeToString(pubPEM)},
			},
		},
	}
	out, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func BenchmarkCreateLogEntryInFlightHeap(b *testing.B) {
	const concurrency = 20
	// ~4MB raw -> ~5.5MB JSON request body (matching prod logs)
	rawReq := makeLargeDSSEPayload(b, 4*1024*1024)

	ranges, err := sharding.NewLogRanges(context.Background(), "", 1, signer.SigningConfig{SigningSchemeOrKeyPath: "memory"})
	if err != nil {
		b.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer lis.Close()
	port := lis.Addr().(*net.TCPAddr).Port

	srv := &blockingTrillianServer{
		arrived: make(chan struct{}, concurrency),
		release: make(chan struct{}),
	}
	grpcSrv := grpc.NewServer()
	trillian.RegisterTrillianLogServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	cm := trillianclient.NewClientManager(nil, trillianclient.GRPCConfig{
		Address: "127.0.0.1",
		Port:    uint16(port),
	})
	defer cm.Close()

	prevAPI := api
	api = &API{
		logRanges:             ranges,
		trillianClientManager: cm,
	}
	defer func() { api = prevAPI }()

	var totalHeapAllocMB, totalHeapInuseMB float64

	for b.Loop() {
		srv.release = make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(concurrency)

		for range concurrency {
			go func() {
				defer wg.Done()
				pe, err := models.UnmarshalProposedEntry(bytes.NewReader(rawReq), nil)
				if err != nil {
					b.Error(err)
					return
				}
				req := httptest.NewRequest("POST", "/api/v1/log/entries", nil)
				CreateLogEntryHandler(entries.CreateLogEntryParams{
					HTTPRequest:   req,
					ProposedEntry: pe,
				})
			}()
		}

		for range concurrency {
			<-srv.arrived
		}

		runtime.GC()
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		totalHeapAllocMB += float64(ms.HeapAlloc) / (1024 * 1024)
		totalHeapInuseMB += float64(ms.HeapInuse) / (1024 * 1024)

		close(srv.release)
		wg.Wait()
	}

	b.ReportMetric(totalHeapAllocMB/float64(b.N), "in-flight-HeapAlloc-MB")
	b.ReportMetric(totalHeapInuseMB/float64(b.N), "in-flight-HeapInuse-MB")
}
