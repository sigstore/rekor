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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
)

type API struct {
	tLogID    int64
	logClient trillian.TrillianLogClient
	pubkey    *keyspb.PublicKey
}

type addResponse struct {
	Status RespStatusCode
}

type getResponse struct {
	Status RespStatusCode
	Leaves []*trillian.LogLeaf
}

type getLatestResponse struct {
	Status RespStatusCode
	Proof  *trillian.GetLatestSignedLogRootResponse
	Key    []byte
}

type getProofResponse struct {
	Status string
	Proof  *trillian.GetInclusionProofByHashResponse
	Key    []byte
}

type getLeafResponse struct {
	Status RespStatusCode
	Leaf   *trillian.GetLeavesByIndexResponse
	Key    []byte
}

type RespStatusCode struct {
	Code string `json:"file_recieved"`
}

func NewAPI() (*API, error) {
	logRpcServer := fmt.Sprintf("%s:%d",
		viper.GetString("trillian_log_server.address"),
		viper.GetUint("trillian_log_server.port"))
	ctx := context.Background()
	tConn, err := dial(ctx, logRpcServer)
	if err != nil {
		return nil, err
	}
	logAdminClient := trillian.NewTrillianAdminClient(tConn)
	logClient := trillian.NewTrillianLogClient(tConn)

	tLogID := viper.GetInt64("trillian_log_server.tlog_id")
	if tLogID == 0 {
		t, err := createAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			return nil, err
		}
		tLogID = t.TreeId
	}

	t, err := logAdminClient.GetTree(ctx, &trillian.GetTreeRequest{
		TreeId: tLogID,
	})
	if err != nil {
		return nil, err
	}

	return &API{
		tLogID:    tLogID,
		logClient: logClient,
		pubkey:    t.PublicKey,
	}, nil
}

type apiHandler func(r *http.Request) (interface{}, error)

func wrap(h apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		r = r.WithContext(log.WithRequestID(ctx, middleware.GetReqID(ctx)))
		defer func() {
			_ = log.RequestIDLogger(r).Sync()
		}()

		respObj, err := h(r)
		if err != nil {
			writeError(w, err)
		}
		b, err := json.Marshal(respObj)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(b))
	}
}

func (api *API) ping(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong!")
}

func (api *API) getHandler(r *http.Request) (interface{}, error) {
	defer r.Body.Close()
	leaf, err := types.ParseRekorLeaf(r.Body)
	if err != nil {
		log.RequestIDLogger(r).Errorf("Not a valid rekor entry: %s", err)
		return nil, err
	}

	byteLeaf, err := json.Marshal(leaf)
	if err != nil {
		return nil, err
	}

	server := serverInstance(api.logClient, api.tLogID)
	resp, err := server.getLeaf(byteLeaf, api.tLogID)
	if err != nil {
		return nil, err
	}
	log.RequestIDLogger(r).Infof("TLOG Response: %s", resp.status)

	logResults := resp.getLeafResult.GetLeaves()

	return getResponse{
		Status: RespStatusCode{Code: getGprcCode(resp.status)},
		Leaves: logResults,
	}, nil
}

func (api *API) getProofHandler(r *http.Request) (interface{}, error) {
	defer r.Body.Close()
	leaf, err := types.ParseRekorLeaf(r.Body)
	if err != nil || leaf.SHA == "" {
		if err == nil {
			err = errors.New("missing SHA sum")
		}
		log.RequestIDLogger(r).Errorf("Not a valid rekor entry: %s", err)
		return nil, err
	}

	byteLeaf, err := json.Marshal(leaf)
	if err != nil {
		return nil, err
	}

	server := serverInstance(api.logClient, api.tLogID)
	resp, err := server.getProof(byteLeaf, api.tLogID)
	if err != nil {
		return nil, err
	}

	log.RequestIDLogger(r).Infof("TLOG PUT Response: %s", resp.status)

	proofResults := resp.getProofResult
	proofResultsJSON, err := json.Marshal(proofResults)
	if err != nil {
		return nil, err
	}

	log.RequestIDLogger(r).Info("Return Proof Result: ", string(proofResultsJSON))

	return getProofResponse{
		Status: getGprcCode(resp.status),
		Proof:  proofResults,
		Key:    api.pubkey.Der,
	}, nil

}

func (api *API) addHandler(r *http.Request) (interface{}, error) {
	defer r.Body.Close()

	var byteEntry bytes.Buffer
	tee := io.TeeReader(r.Body, &byteEntry)

	// See if this is a valid RekorLeaf
	rekorLeaf, err := types.ParseRekorLeaf(tee)
	if err != nil {
		log.RequestIDLogger(r).Errorf("Not a valid rekor entry: %s", err)
		return nil, err
	}

	// Check to see if the entry already exists, only if we have a full leaf
	server := serverInstance(api.logClient, api.tLogID)
	if rekorLeaf.SHA != "" {
		byteLeaf, err := json.Marshal(rekorLeaf)
		if err != nil {
			return nil, err
		}

		if resp, err := server.getLeaf(byteLeaf, api.tLogID); err != nil && len(resp.getLeafResult.Leaves) != 0 {
			return addResponse{
				Status: RespStatusCode{Code: getGprcCode(codes.AlreadyExists)},
			}, nil
		}
	}

	rekorEntry, err := types.ParseRekorEntry(&byteEntry, rekorLeaf)
	if err != nil {
		return nil, err
	}

	// Now load/validate it before adding. This can be expensive, so we first check if the data already exists.
	if err := rekorEntry.Load(r.Context()); err != nil {
		return nil, err
	}

	leafToAdd, err := json.Marshal(&(rekorEntry.RekorLeaf))
	if err != nil {
		return nil, err
	}

	resp, err := server.addLeaf(leafToAdd, api.tLogID)
	if err != nil {
		return nil, err
	}

	log.RequestIDLogger(r).Infof("Server PUT Response: %s", resp.status)

	return addResponse{
		Status: RespStatusCode{Code: getGprcCode(resp.status)},
	}, nil
}

func (api *API) getLatestHandler(r *http.Request) (interface{}, error) {
	lastSizeInt := int64(0)
	lastSize := r.URL.Query().Get("lastSize")
	log.RequestIDLogger(r).Info("Last Tree Recieved: ", lastSize)
	if lastSize != "" {
		var err error
		lastSizeInt, err = strconv.ParseInt(lastSize, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	server := serverInstance(api.logClient, api.tLogID)

	resp, err := server.getLatest(api.tLogID, lastSizeInt)
	if err != nil {
		return nil, err
	}

	return getLatestResponse{
		Status: RespStatusCode{Code: getGprcCode(resp.status)},
		Proof:  resp.getLatestResult,
		Key:    api.pubkey.Der,
	}, nil
}

func (api *API) getLeafByIndexHandler(r *http.Request) (interface{}, error) {
	leafSizeInt := int64(0)
	leafIndex := r.URL.Query().Get("leafindex")

	// error check leaf index

	if leafIndex != "" {
		var err error
		leafSizeInt, err = strconv.ParseInt(leafIndex, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	server := serverInstance(api.logClient, api.tLogID)

	resp, err := server.getLeafByIndex(api.tLogID, leafSizeInt)
	if err != nil {
		return nil, err
	}

	respJSON, err := json.Marshal(resp.getLeafByIndexResult)
	if err != nil {
		return nil, err
	}

	log.RequestIDLogger(r).Info("Return getLeafByIndex :", string(respJSON))

	return getLeafResponse{
		Status: RespStatusCode{Code: getGprcCode(resp.status)},
		Leaf:   resp.getLeafByIndexResult,
		Key:    api.pubkey.Der,
	}, nil
}

func New() (*chi.Mux, error) {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	api, err := NewAPI()
	if err != nil {
		return nil, err
	}
	router.Post("/api/v1/add", wrap(api.addHandler))
	router.Post("/api/v1/get", wrap(api.getHandler))
	router.Post("/api/v1/getproof", wrap(api.getProofHandler))
	router.Post("/api/v1/latest", wrap(api.getLatestHandler))
	router.Get("/api/v1/getleaf", wrap(api.getLeafByIndexHandler))
	router.Get("/api/v1//ping", api.ping)
	return router, nil
}

func writeError(w http.ResponseWriter, err error) {
	log.Logger.Error(err)
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "Server error: %v\n", err)
}
