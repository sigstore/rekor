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
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	logType     string
	enablePprof bool
	// these map to the operationId as defined in openapi.yaml file
	operationIds = []string{
		"searchIndex",
		"getLogInfo",
		"getPublicKey",
		"getLogProof",
		"createLogEntry",
		"getLogEntryByIndex",
		"getLogEntryByUUID",
		"searchLogQuery",
	}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rekor-server",
	Short: "Rekor signature transparency log server",
	Long: `Rekor fulfills the signature transparency role of sigstore's software
	signing infrastructure. It can also be run on its own and is designed to be
	extensible to work with different manifest schemas and PKI tooling`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rekor-server.yaml)")
	rootCmd.PersistentFlags().StringVar(&logType, "log_type", "dev", "logger type to use (dev/prod)")
	rootCmd.PersistentFlags().BoolVar(&enablePprof, "enable_pprof", false, "enable pprof for profiling on port 6060")
	rootCmd.PersistentFlags().Bool("enable_killswitch", false, "enable killswitch for TESTING ONLY on port 2345")
	_ = rootCmd.PersistentFlags().MarkHidden("enable_killswitch")

	rootCmd.PersistentFlags().String("trillian_log_server.address", "127.0.0.1", "Trillian log server address")
	rootCmd.PersistentFlags().Uint16("trillian_log_server.port", 8090, "Trillian log server port")
	rootCmd.PersistentFlags().Uint("trillian_log_server.tlog_id", 0, "Trillian tree id")
	rootCmd.PersistentFlags().String("trillian_log_server.sharding_config", "", "path to config file for inactive shards, in JSON or YAML")

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	rootCmd.PersistentFlags().String("rekor_server.hostname", hostname, "public hostname of instance")
	rootCmd.PersistentFlags().String("rekor_server.address", "127.0.0.1", "Address to bind to")

	rootCmd.PersistentFlags().String("rekor_server.signer", "memory",
		`Rekor signer to use. Valid options are: [gcpkms, memory, filename containing PEM encoded private key].
Memory and file-based signers should only be used for testing.`)
	rootCmd.PersistentFlags().String("rekor_server.signer-passwd", "", "Password to decrypt signer private key")

	rootCmd.PersistentFlags().Uint16("port", 3000, "Port to bind to")

	rootCmd.PersistentFlags().Bool("enable_retrieve_api", true, "enables Redis-based index API endpoint")
	_ = rootCmd.PersistentFlags().MarkDeprecated("enable_retrieve_api", "this flag is deprecated in favor of enabled_api_endpoints (searchIndex)")
	rootCmd.PersistentFlags().String("redis_server.address", "127.0.0.1", "Redis server address")
	rootCmd.PersistentFlags().Uint16("redis_server.port", 6379, "Redis server port")

	rootCmd.PersistentFlags().Bool("enable_attestation_storage", false, "enables rich attestation storage")
	rootCmd.PersistentFlags().String("attestation_storage_bucket", "", "url for attestation storage bucket")
	rootCmd.PersistentFlags().Int("max_attestation_size", 100*1024, "max size for attestation storage, in bytes")

	rootCmd.PersistentFlags().StringSlice("enabled_api_endpoints", operationIds, "list of API endpoints to enable using operationId from openapi.yaml")

	rootCmd.PersistentFlags().Uint64("max_request_body_size", 0, "maximum size for HTTP request body, in bytes; set to 0 for unlimited")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	log.Logger.Debugf("pprof enabled %v", enablePprof)
	// Enable pprof
	if enablePprof {
		go func() {
			mux := http.NewServeMux()

			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/{action}", pprof.Index)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

			srv := &http.Server{
				Addr:         ":6060",
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
				Handler:      mux,
			}

			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Logger.Fatalf("Error when starting or running http server: %v", err)
			}
		}()
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName("rekor-server")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}
