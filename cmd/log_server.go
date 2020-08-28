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
	"bytes"
	"context"
	"crypto"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tcrypto "github.com/google/trillian/crypto"
)

type server struct {
	client        trillian.TrillianLogClient
	logID         int64
	MinMergeDelay time.Duration
	root          types.LogRootV1
	rootLock      sync.Mutex
	updateLock    sync.Mutex
	ctx           context.Context
	Hasher        hashers.LogHasher
	PubKey        crypto.PublicKey
	SigHash       crypto.Hash
	v             merkle.LogVerifier
}

type Response struct {
	status   string
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
		log.Printf("Server Status: Bad status: %v", resp.QueuedLeaf.GetStatus())
	}
	if c == codes.OK {
		log.Println("Trillian LeafHash Value created for ", string(byteValue))
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

	for _, logLeaf := range resp.GetLeaves() {
		leafValue := logLeaf.GetLeafValue()
		log.Printf("[hashleaf integrity passed: ] %s", leafValue)
	}

	return &Response{
		status: "ok",
	}, nil
}

func (s *server) getRoot() *types.LogRootV1 {
	s.rootLock.Lock()
	defer s.rootLock.Unlock()

	// Copy the internal trusted root in order to prevent clients from modifying it.
	ret := s.root
	return &ret
}

// verifyInclusionByHash verifies that the inclusion proof for the given Merkle leafHash
// matches the given trusted root.
func (s *server) verifyInclusionByHash(trusted *types.LogRootV1, leafHash []byte, proof *trillian.Proof) error {
	if trusted == nil {
		return fmt.Errorf("verifyInclusionByHash() error: trusted == nil")
	}
	if proof == nil {
		return fmt.Errorf("verifyInclusionByHash() error: proof == nil")
	}

	return s.v.VerifyInclusionProof(proof.LeafIndex, int64(trusted.TreeSize), proof.Hashes,
		trusted.RootHash, leafHash)
}

func (s *server) getAndVerifyInclusionProof(ctx context.Context, leafHash []byte, sth *types.LogRootV1) (bool, error) {
	resp, err := s.client.GetInclusionProofByHash(ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    s.logID,
			LeafHash: leafHash,
			TreeSize: int64(sth.TreeSize),
		})
	if err != nil {
		return false, err
	}
	if len(resp.Proof) < 1 {
		return false, nil
	}
	for _, proof := range resp.Proof {
		if err := s.verifyInclusionByHash(sth, leafHash, proof); err != nil {
			return false, fmt.Errorf("verifyInclusionByHash(): %v", err)
		}
	}
	return true, nil
}

func (s *server) BuildLeaf(byteValue []byte) *trillian.LogLeaf {
	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(byteValue)
	fmt.Println("lefafhsa:", leafHash)

	return &trillian.LogLeaf{
		LeafValue:      byteValue,
		MerkleLeafHash: leafHash,
	}
}

// VerifyRoot verifies that newRoot is a valid append-only operation from
// trusted. If trusted.TreeSize is zero, a consistency proof is not needed.
func (s *server) VerifyRoot(trusted *types.LogRootV1, newRoot *trillian.SignedLogRoot, consistency [][]byte) (*types.LogRootV1, error) {

	if trusted == nil {
		return nil, fmt.Errorf("VerifyRoot() error: trusted == nil")
	}
	if newRoot == nil {
		return nil, fmt.Errorf("VerifyRoot() error: newRoot == nil")
	}

	// Verify SignedLogRoot signature and unpack its contents.
	fmt.Println("PubKey", s.PubKey)
	fmt.Println("SigHash", s.SigHash)
	fmt.Println("newRoot", newRoot)
	r, err := tcrypto.VerifySignedLogRoot(s.PubKey, s.SigHash, newRoot)
	if err != nil {
		return nil, err
	}

	// Implicitly trust the first root we get.
	if trusted.TreeSize != 0 {
		// Verify consistency proof.
		if err := s.v.VerifyConsistencyProof(int64(trusted.TreeSize), int64(r.TreeSize), trusted.RootHash, r.RootHash, consistency); err != nil {
			return nil, fmt.Errorf("failed to verify consistency proof from %d->%d %x->%x: %v", trusted.TreeSize, r.TreeSize, trusted.RootHash, r.RootHash, err)
		}
	}
	return r, nil
}

// getAndVerifyLatestRoot fetches and verifies the latest root against a trusted root, seen in the past.
// Pass nil for trusted if this is the first time querying this log.
func (s *server) getAndVerifyLatestRoot(ctx context.Context, trusted *types.LogRootV1) (*types.LogRootV1, error) {
	resp, err := s.client.GetLatestSignedLogRoot(ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId:         s.logID,
			FirstTreeSize: int64(trusted.TreeSize),
		})
	if err != nil {
		return nil, err
	}

	// TODO(gbelvin): Turn on root verification.
	/*
		logRoot, err := c.VerifyRoot(&types.LogRootV1{}, resp.GetSignedLogRoot(), nil)
		if err != nil {
			return nil, err
		}
	*/
	// TODO(gbelvin): Remove this hack when all implementations store digital signatures.
	var logRoot types.LogRootV1
	if err := logRoot.UnmarshalBinary(resp.GetSignedLogRoot().LogRoot); err != nil {
		return nil, err
	}

	if trusted.TreeSize > 0 &&
		logRoot.TreeSize == trusted.TreeSize &&
		bytes.Equal(logRoot.RootHash, trusted.RootHash) {
		// Tree has not been updated.
		return &logRoot, nil
	}

	// Verify root update if the tree / the latest signed log root isn't empty.
	if logRoot.TreeSize > 0 {
		if _, err := s.VerifyRoot(trusted, resp.GetSignedLogRoot(), resp.GetProof().GetHashes()); err != nil {
			return nil, err
		}
	}
	return &logRoot, nil
}

// UpdateRoot retrieves the current SignedLogRoot, verifying it against roots this client has
// seen in the past, and updating the currently trusted root if the new root verifies, and is
// newer than the currently trusted root.
func (s *server) UpdateRoot(ctx context.Context) (*types.LogRootV1, error) {
	// Only one root update should be running at any point in time, because
	// the update involves a consistency proof from the old value, and if the
	// old value could change along the way (in another goroutine) then the
	// result could be inconsistent.
	//
	// For example, if the current root is A and two root updates A->B and A->C
	// happen in parallel, then we might end up with the transitions A->B->C:
	//     cur := A            cur := A
	//    getRoot() => B      getRoot() => C
	//    proof(A->B) ok      proof(A->C) ok
	//    c.root = B
	//                        c.root = C
	// and the last step (B->C) has no proof and so could hide a forked tree.
	s.updateLock.Lock()
	defer s.updateLock.Unlock()

	currentlyTrusted := s.getRoot()
	newTrusted, err := s.getAndVerifyLatestRoot(ctx, currentlyTrusted)
	if err != nil {
		return nil, err
	}

	// Lock "rootLock" for the "root" update.
	s.rootLock.Lock()
	defer s.rootLock.Unlock()

	if newTrusted.TimestampNanos > currentlyTrusted.TimestampNanos &&
		newTrusted.TreeSize >= currentlyTrusted.TreeSize {

		// Take a copy of the new trusted root in order to prevent clients from modifying it.
		s.root = *newTrusted

		return newTrusted, nil
	}

	return nil, nil
}

// WaitForRootUpdate repeatedly fetches the latest root until there is an
// update, which it then applies, or until ctx times out.
func (s *server) WaitForRootUpdate(ctx context.Context) (*types.LogRootV1, error) {
	b := &backoff.Backoff{
		Min:    100 * time.Millisecond,
		Max:    10 * time.Second,
		Factor: 2,
		Jitter: true,
	}

	for {
		newTrusted, err := s.UpdateRoot(ctx)
		switch status.Code(err) {
		case codes.OK:
			if newTrusted != nil {
				return newTrusted, nil
			}
		case codes.Unavailable, codes.NotFound, codes.FailedPrecondition:
			// Retry.
		default:
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, status.Errorf(codes.DeadlineExceeded, "%v", ctx.Err())
		case <-time.After(b.Duration()):
		}
	}
}

func (s *server) verifyInclusion(ctx context.Context, byteValue []byte, tlog_id int64) error {

	leaf := s.BuildLeaf(byteValue)

	if s.MinMergeDelay > 0 {
		select {
		case <-s.ctx.Done():
			return status.Errorf(codes.DeadlineExceeded, "%v", s.ctx.Err())
		case <-time.After(s.MinMergeDelay):
		}
	}

	var root *types.LogRootV1
	for {
		root = s.getRoot()

		// It is illegal to ask for an inclusion proof with TreeSize = 0.
		if root.TreeSize >= 1 {
			ok, err := s.getAndVerifyInclusionProof(ctx, leaf.MerkleLeafHash, root)
			if err != nil && status.Code(err) != codes.NotFound {
				return err
			} else if ok {
				return nil
			}
		}

		// If not found or tree is empty, wait for a root update before retrying again.
		if _, err := s.WaitForRootUpdate(ctx); err != nil {
			return err
		}
	}
}

// func (s *server) getLeaf(r *Request) (*Response, error) {
