//
// Copyright 2025 The Sigstore Authors.
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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/sigstore/rekor/pkg/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ClientManager creates and caches Trillian clients and their underlying gRPC connections.
type ClientManager struct {
	// Mutex for connections map
	connMu sync.RWMutex
	// connections maps a specific gRPC configuration to a shared connection pool.
	connections map[GRPCConfig]*grpc.ClientConn

	// Mutex for trillianClients map
	clientMu sync.RWMutex
	// trillianClients caches the TrillianClient wrappers.
	trillianClients map[int64]*TrillianClient
	// flag to indicate whether the client manager is shutting down
	shutdown bool

	// treeIDToConfig maps a specific tree ID to its gRPC configuration.
	treeIDToConfig map[int64]GRPCConfig
	// defaultConfig is the global fallback configuration.
	defaultConfig GRPCConfig
}

// NewClientManager creates a new ClientManager.
func NewClientManager(treeIDToConfig map[int64]GRPCConfig, defaultConfig GRPCConfig) *ClientManager {
	return &ClientManager{
		connections:     make(map[GRPCConfig]*grpc.ClientConn),
		treeIDToConfig:  treeIDToConfig,
		defaultConfig:   defaultConfig,
		trillianClients: make(map[int64]*TrillianClient),
	}
}

// getConn finds the correct gRPC config for a tree ID, then dials or retrieves a cached connection.
func (cm *ClientManager) getConn(treeID int64) (*grpc.ClientConn, error) {
	// Determine the correct GRPCConfig for this treeID.
	config, ok := cm.treeIDToConfig[treeID]
	if !ok {
		// If no specific config exists, fall back to the global default.
		config = cm.defaultConfig
	}

	cm.connMu.RLock()
	conn, ok := cm.connections[config]
	cm.connMu.RUnlock()
	if ok {
		return conn, nil
	}

	cm.connMu.Lock()
	defer cm.connMu.Unlock()
	// Double-check after acquiring the write lock.
	conn, ok = cm.connections[config]
	if ok {
		return conn, nil
	}

	// Dial and cache the new connection.
	newConn, err := dial(config.Address, config.Port, config.TLSCACert, config.UseSystemTrustStore, config.GRPCServiceConfig)
	if err != nil {
		return nil, err
	}
	cm.connections[config] = newConn
	return newConn, nil
}

// GetTrillianClient returns a Rekor Trillian client wrapper for the given tree ID.
func (cm *ClientManager) GetTrillianClient(treeID int64) (*TrillianClient, error) {
	cm.clientMu.RLock()
	if cm.shutdown {
		cm.clientMu.RUnlock()
		return nil, errors.New("client manager is shutting down")
	}
	client, ok := cm.trillianClients[treeID]
	cm.clientMu.RUnlock()
	if ok {
		return client, nil
	}

	conn, err := cm.getConn(treeID)
	if err != nil {
		return nil, err
	}

	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()
	// Double-check after acquiring the write lock.
	if cm.shutdown {
		return nil, errors.New("client manager is shutting down")
	}
	if client, ok = cm.trillianClients[treeID]; ok {
		return client, nil
	}

	newClient := newTrillianClient(trillian.NewTrillianLogClient(conn), treeID)
	cm.trillianClients[treeID] = newClient
	return newClient, nil
}

func CreateAndInitTree(ctx context.Context, config GRPCConfig) (*trillian.Tree, error) {
	newConn, err := dial(config.Address, config.Port, config.TLSCACert, config.UseSystemTrustStore, config.GRPCServiceConfig)
	if err != nil {
		return nil, err
	}
	adminClient := trillian.NewTrillianAdminClient(newConn)

	t, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:        trillian.TreeType_LOG,
			TreeState:       trillian.TreeState_ACTIVE,
			MaxRootDuration: durationpb.New(time.Hour),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create tree: %w", err)
	}
	logClient := trillian.NewTrillianLogClient(newConn)

	if err := client.InitLog(ctx, t, logClient); err != nil {
		return nil, fmt.Errorf("init log: %w", err)
	}
	log.Logger.Infof("Created new tree with ID: %v", t.TreeId)
	return t, nil
}

func dial(hostname string, port uint16, tlsCACertFile string, useSystemTrustStore bool, serviceConfig string) (*grpc.ClientConn, error) {
	// Set up and test connection to rpc server
	var creds credentials.TransportCredentials
	switch {
	case useSystemTrustStore:
		creds = credentials.NewTLS(&tls.Config{
			ServerName: hostname,
			MinVersion: tls.VersionTLS12,
		})
	case tlsCACertFile != "":
		tlsCaCert, err := os.ReadFile(filepath.Clean(tlsCACertFile))
		if err != nil {
			return nil, fmt.Errorf("failed to load tls_ca_cert: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(tlsCaCert) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}
		creds = credentials.NewTLS(&tls.Config{
			ServerName: hostname,
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		})
	default:
		creds = insecure.NewCredentials()
	}

	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if serviceConfig != "" {
		opts = append(opts, grpc.WithDefaultServiceConfig(serviceConfig))
	}
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", hostname, port), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC server: %w", err)
	}

	return conn, nil
}

// Close stops clients and closes underlying gRPC connections.
func (cm *ClientManager) Close() error {
	var err error

	// set shutdown flag to true and clear cache of clients
	cm.clientMu.Lock()
	cm.shutdown = true
	cm.trillianClients = make(map[int64]*TrillianClient)
	cm.clientMu.Unlock()

	cm.connMu.Lock()
	for cfg, conn := range cm.connections {
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close conn %v:%d: %w", cfg.Address, cfg.Port, closeErr))
		}
		delete(cm.connections, cfg)
	}
	cm.connMu.Unlock()
	return err
}
