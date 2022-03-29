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
	"net/http"

	"github.com/go-openapi/loads"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor/pkg/api"
	"github.com/sigstore/rekor/pkg/generated/restapi"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types/alpine"
	alpine_v001 "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/helm"
	helm_v001 "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
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
	Run: func(cmd *cobra.Command, args []string) {

		// Setup the logger to dev/prod
		log.ConfigureLogger(viper.GetString("log_type"))

		// workaround for https://github.com/sigstore/rekor/issues/68
		// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
		_ = flag.CommandLine.Parse([]string{})

		vi := version.GetVersionInfo()
		viStr, err := vi.JSONString()
		if err != nil {
			viStr = vi.String()
		}
		log.Logger.Infof("starting rekor-server @ %v", viStr)

		doc, _ := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
		server := restapi.NewServer(operations.NewRekorServerAPI(doc))
		defer func() {
			if err := server.Shutdown(); err != nil {
				log.Logger.Error(err)
			}
		}()

		//TODO: make this a config option for server to load via viper field
		//TODO: add command line option to print versions supported in binary

		// these trigger loading of package and therefore init() methods to run
		pluggableTypeMap := map[string]string{
			rekord.KIND:       rekord_v001.APIVERSION,
			rpm.KIND:          rpm_v001.APIVERSION,
			jar.KIND:          jar_v001.APIVERSION,
			intoto.KIND:       intoto_v001.APIVERSION,
			rfc3161.KIND:      rfc3161_v001.APIVERSION,
			alpine.KIND:       alpine_v001.APIVERSION,
			helm.KIND:         helm_v001.APIVERSION,
			tuf.KIND:          tuf_v001.APIVERSION,
			hashedrekord.KIND: hashedrekord_v001.APIVERSION,
		}

		for k, v := range pluggableTypeMap {
			log.Logger.Infof("Loading support for pluggable type '%v'", k)
			log.Logger.Infof("Loading version '%v' for pluggable type '%v'", v, k)
		}

		server.Host = viper.GetString("rekor_server.address")
		server.Port = int(viper.GetUint("port"))
		server.EnabledListeners = []string{"http"}

		// Update logRangeMap if flag was passed in
		shardingConfig := viper.GetString("trillian_log_server.sharding_config")
		treeID := viper.GetUint("trillian_log_server.tlog_id")

		ranges, err := sharding.NewLogRanges(shardingConfig, treeID)
		if err != nil {
			log.Logger.Fatalf("unable get sharding details from sharding config: %v", err)
		}

		api.ConfigureAPI(ranges, treeID)
		server.ConfigureAPI()

		http.Handle("/metrics", promhttp.Handler())
		go func() {
			_ = http.ListenAndServe(":2112", nil)
		}()

		if err := server.Serve(); err != nil {
			log.Logger.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
