// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright 2021 The Sigstore Authors.
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
//

package index

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// SearchIndexHandlerFunc turns a function with the right signature into a search index handler
type SearchIndexHandlerFunc func(SearchIndexParams) middleware.Responder

// Handle executing the request and returning a response
func (fn SearchIndexHandlerFunc) Handle(params SearchIndexParams) middleware.Responder {
	return fn(params)
}

// SearchIndexHandler interface for that can handle valid search index params
type SearchIndexHandler interface {
	Handle(SearchIndexParams) middleware.Responder
}

// NewSearchIndex creates a new http.Handler for the search index operation
func NewSearchIndex(ctx *middleware.Context, handler SearchIndexHandler) *SearchIndex {
	return &SearchIndex{Context: ctx, Handler: handler}
}

/* SearchIndex swagger:route POST /api/v1/index/retrieve index searchIndex

Searches index by entry metadata

EXPERIMENTAL - this endpoint is offered as best effort only and may be changed or removed in future releases.
The results returned from this endpoint may be incomplete.


*/
type SearchIndex struct {
	Context *middleware.Context
	Handler SearchIndexHandler
}

func (o *SearchIndex) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSearchIndexParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
