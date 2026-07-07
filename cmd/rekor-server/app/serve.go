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

package app

import (
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/profiler"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-openapi/loads"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor/pkg/api"
	"github.com/sigstore/rekor/pkg/generated/restapi"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/alpine"
	alpine_v001 "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/cose"
	cose_v001 "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/dsse"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/helm"
	helm_v001 "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	"github.com/sigstore/rekor/pkg/types/jar"
	jar_v001 "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/rekord"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/rfc3161"
	rfc3161_v001 "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/rpm"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/tuf"
	tuf_v001 "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start http server with configured api",
	Long:  `Starts a http server and serves the configured api`,
	Run: func(_ *cobra.Command, _ []string) {
		// Setup the logger to dev/prod
		log.ConfigureLogger(viper.GetString("log_type"), viper.GetString("trace-string-prefix"))

		// workaround for https://github.com/sigstore/rekor/issues/68
		// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
		_ = flag.CommandLine.Parse([]string{})

		vi := version.GetVersionInfo()
		viStr, err := vi.JSONString()
		if err != nil {
			viStr = vi.String()
		}
		log.Logger.Infof("starting rekor-server @ %v", viStr)

		// overrides the correlation ID printed in logs, if config is set
		middleware.RequestIDHeader = viper.GetString("http-request-id-header-name")

		if viper.GetBool("gcp_cloud_profiling.enabled") {
			cfg := profiler.Config{
				Service:           viper.GetString("gcp_cloud_profiling.service"),
				ServiceVersion:    viper.GetString("gcp_cloud_profiling.service_version"),
				ProjectID:         viper.GetString("gcp_cloud_profiling.project_id"),
				EnableOCTelemetry: viper.GetBool("gcp_cloud_profiling.enable_oc_telemetry"),
			}

			if err := profiler.Start(cfg); err != nil {
				log.Logger.Warnf("Error configuring GCP Cloud Profiling: %v", err)
			}
		}

		doc, _ := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
		server := restapi.NewServer(operations.NewRekorServerAPI(doc))
		defer func() {
			if err := server.Shutdown(); err != nil {
				log.Logger.Error(err)
			}
		}()
		// These trigger loading of the package and therefore init() methods to run,
		// which registers each type's constructor in types.TypeMap.
		entryTypeMap := map[string][]string{
			rekord.KIND:       {rekord_v001.APIVERSION},
			rpm.KIND:          {rpm_v001.APIVERSION},
			jar.KIND:          {jar_v001.APIVERSION},
			intoto.KIND:       {intoto_v001.APIVERSION, intoto_v002.APIVERSION},
			cose.KIND:         {cose_v001.APIVERSION},
			rfc3161.KIND:      {rfc3161_v001.APIVERSION},
			alpine.KIND:       {alpine_v001.APIVERSION},
			helm.KIND:         {helm_v001.APIVERSION},
			tuf.KIND:          {tuf_v001.APIVERSION},
			hashedrekord.KIND: {hashedrekord_v001.APIVERSION},
			dsse.KIND:         {dsse_v001.APIVERSION},
		}

		// Using --enabled_entry_types, restrict which kinds the server will
		// accept for new submissions. By default, support every type compiled
		// into the binary.
		requestedTypes := viper.GetStringSlice("enabled_entry_types")
		enabledTypes, err := filterEntryTypes(entryTypeMap, requestedTypes)
		if err != nil {
			log.Logger.Fatalf("invalid --enabled_entry_types flag: %v", err)
		}
		types.SetAllowedKindsForSubmission(enabledTypes)

		for _, k := range enabledTypes {
			log.Logger.Infof("Loading support for entry type '%v'", k)
			log.Logger.Infof("Loading version '%v' for entry type '%v'", entryTypeMap[k], k)
		}

		server.Host = viper.GetString("rekor_server.address")
		server.Port = int(viper.GetUint("port"))
		server.EnabledListeners = []string{"http"}

		treeID := viper.GetInt64("trillian_log_server.tlog_id")

		api.ConfigureAPI(treeID)
		server.ConfigureAPI()

		http.Handle("/metrics", promhttp.Handler())
		go func() {
			srv := &http.Server{
				Addr:         ":2112",
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			_ = srv.ListenAndServe()
		}()

		if err := server.Serve(); err != nil {
			log.Logger.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

// filterEntryTypes filters the list of compiled-in entry types
// down to the set requested via the --enabled_entry_types flag.
// If any requested type is not present, an error is returned.
// Note that filtering only affects the write path, not the read paths.
func filterEntryTypes(allTypes map[string][]string, requestedTypes []string) ([]string, error) {
	enabled := make(map[string]struct{})
	for _, kind := range requestedTypes {
		_, ok := allTypes[kind]
		if !ok {
			known := make([]string, 0, len(allTypes))
			for k := range allTypes {
				known = append(known, k)
			}
			sort.Strings(known)
			return nil, fmt.Errorf("unknown entry type %q; compiled-in types are: %s",
				kind, strings.Join(known, ", "))
		}
		enabled[kind] = struct{}{}
	}
	enabledKinds := make([]string, 0, len(enabled))
	for k := range enabled {
		enabledKinds = append(enabledKinds, k)
	}
	return enabledKinds, nil
}
