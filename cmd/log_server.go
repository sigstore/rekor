/*
Copyright © 2020 Luke Hinds <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"context"
	"fmt"
	"github.com/google/trillian"
	"github.com/google/trillian/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"log"
)

type server struct {
	client trillian.TrillianLogClient
	logID  int64
	ctx    context.Context
}

type Response struct {
	status string
	leafhash string
}

func serverInstance(client trillian.TrillianLogClient, tLogID int64) *server {
	return &server{
		client: client,
		logID:  tLogID,
	}
}

func (s *server) addLeaf(byteValue []byte, tLogID int64) (*Response, error) {

	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: tLogID,
		Leaf:  leaf,
	}
	resp, err := s.client.QueueLeaf(context.Background(), rqst)
	if err != nil {
		fmt.Println(err)
	}

	c := codes.Code(resp.QueuedLeaf.GetStatus().GetCode())
	if c != codes.OK && c != codes.AlreadyExists {
		fmt.Errorf("Server Status: Bad status: %v", resp.QueuedLeaf.GetStatus())
	}
	if c == codes.OK {
		log.Println("Server status: ok")
	} else if c == codes.AlreadyExists {
		log.Printf("Data already Exists")
	}

	return &Response{
		status: "OK",
	}, nil
}

func (s *server) getLeaf(byteValue []byte, tlog_id int64) (*Response, error) {

	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(byteValue)

	rqst := &trillian.GetLeavesByHashRequest{
		LogId:    tlog_id,
		LeafHash: [][]byte{leafHash},
	}

	resp, err := s.client.GetLeavesByHash(context.Background(), rqst)
	if err != nil {
		log.Fatal(err)
	}

	for i, logLeaf := range resp.GetLeaves() {
		leafValue := logLeaf.GetLeafValue()
		log.Printf("[server:get] %d: %s", i, leafValue)
	}

	return &Response{
		status: "ok",
	}, nil
}
