/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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
// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/mitchellh/mapstructure"

	pkgapi "github.com/projectrekor/rekor/pkg/api"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/entries"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations/tlog"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/util"

	"github.com/urfave/negroni"
)

//go:generate swagger generate server --target ../../generated --name RekorServer --spec ../../../openapi.yaml --principal interface{} --exclude-main

func configureFlags(api *operations.RekorServerAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.RekorServerAPI) http.Handler {
	// configure the api here
	api.ServeError = logAndServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf
	api.Logger = log.Logger.Infof

	// api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()
	api.JSONProducer = runtime.JSONProducer()

	api.YamlConsumer = util.YamlConsumer()
	api.YamlProducer = util.YamlProducer()

	api.EntriesCreateLogEntryHandler = entries.CreateLogEntryHandlerFunc(pkgapi.CreateLogEntryHandler)
	api.EntriesGetLogEntryByIndexHandler = entries.GetLogEntryByIndexHandlerFunc(pkgapi.GetLogEntryByIndexHandler)
	api.EntriesGetLogEntryByUUIDHandler = entries.GetLogEntryByUUIDHandlerFunc(pkgapi.GetLogEntryByUUIDHandler)
	api.EntriesGetLogEntryProofHandler = entries.GetLogEntryProofHandlerFunc(pkgapi.GetLogEntryProofHandler)
	api.EntriesSearchLogQueryHandler = entries.SearchLogQueryHandlerFunc(pkgapi.SearchLogQueryHandler)

	api.TlogGetLogInfoHandler = tlog.GetLogInfoHandlerFunc(pkgapi.GetLogInfoHandler)
	api.TlogGetLogProofHandler = tlog.GetLogProofHandlerFunc(pkgapi.GetLogProofHandler)

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	//not cacheable
	api.AddMiddlewareFor("GET", "/api/v1/log", middleware.NoCache)
	api.AddMiddlewareFor("GET", "/api/v1/log/proof", middleware.NoCache)
	api.AddMiddlewareFor("GET", "/api/v1/log/entries/{entryUUID}/proof", middleware.NoCache)

	//cache forever
	api.AddMiddlewareFor("GET", "/api/v1/log/entries", cacheForever)
	api.AddMiddlewareFor("GET", "/api/v1/log/entries/{entryUUID}", cacheForever)

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	returnHandler := middleware.Recoverer(handler)
	returnHandler = middleware.Logger(returnHandler)
	returnHandler = middleware.Heartbeat("/ping")(returnHandler)

	// add the Trillian API object in context for all endpoints
	returnHandler = addTrillianAPI(handler)
	return middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		r = r.WithContext(log.WithRequestID(ctx, middleware.GetReqID(ctx)))
		defer func() {
			_ = log.RequestIDLogger(r).Sync()
		}()

		returnHandler.ServeHTTP(w, r)
	}))
}

func cacheForever(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := negroni.NewResponseWriter(w)
		ww.Before(func(w negroni.ResponseWriter) {
			if w.Status() >= 200 && w.Status() <= 299 {
				w.Header().Set("Cache-Control", "s-maxage=31536000, max-age=31536000, immutable")
			}
		})
		handler.ServeHTTP(ww, r)
	})
}

func addTrillianAPI(handler http.Handler) http.Handler {
	api, err := pkgapi.NewAPI()
	if err != nil {
		log.Logger.Panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCtx := pkgapi.AddAPIToContext(r.Context(), api)
		handler.ServeHTTP(w, r.WithContext(apiCtx))
	})
}

func logAndServeError(w http.ResponseWriter, r *http.Request, err error) {
	log.RequestIDLogger(r).Error(err)
	requestFields := map[string]interface{}{}
	if err := mapstructure.Decode(r, &requestFields); err == nil {
		log.RequestIDLogger(r).Debug(requestFields)
	}
	errors.ServeError(w, r, err)
}
