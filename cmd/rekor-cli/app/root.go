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
	"runtime/debug"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/pkg/log"

	// these imports are to call the packages' init methods
	_ "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
)

var rootCmd = &cobra.Command{
	Use:   "rekor",
	Short: "Rekor CLI",
	Long:  `Rekor command line interface tool`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig(cmd)
	},
}

// Execute runs the base CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.CliLogger.Fatal(err)
	}
}

func init() {
	initializePFlagMap()
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.rekor.yaml)")
	rootCmd.PersistentFlags().Bool("store_tree_state", true, "whether to store tree state in between invocations for additional verification")

	rootCmd.PersistentFlags().Var(NewFlagValue(urlFlag, "https://rekor.sigstore.dev"), "rekor_server", "Server address:port")
	rootCmd.PersistentFlags().Var(NewFlagValue(formatFlag, "default"), "format", "Command output format")
	rootCmd.PersistentFlags().Var(NewFlagValue(timeoutFlag, "30s"), "timeout", "HTTP timeout")

	rootCmd.PersistentFlags().String("api-key", "", "API key for rekor.sigstore.dev")

	// these are bound here and not in PreRun so that all child commands can use them
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.CliLogger.Fatal(err)
	}

	// look for the default version and replace it, if found, from runtime build info
	if GitVersion != "devel" {
		return
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	// Version is set in artifacts built with -X github.com/sigstore/rekor/cmd/rekor-cli/app.GitVersion=1.2.3
	// Ensure version is also set when installed via go install github.com/sigstore/rekor/cmd/rekor-cli
	GitVersion = bi.Main.Version
}

func initConfig(cmd *cobra.Command) error {

	viper.SetEnvPrefix("rekor")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// manually set all values provided from viper through pflag validation logic
	var changedFlags []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed && viper.IsSet(f.Name) {
			changedFlags = append(changedFlags, f.Name)
		}
	})

	for _, flag := range changedFlags {
		val := viper.Get(flag)
		if err := cmd.Flags().Set(flag, fmt.Sprintf("%v", val)); err != nil {
			return err
		}
	}

	if viper.GetString("config") != "" {
		viper.SetConfigFile(viper.GetString("config"))
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return err
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".rekor")
	}

	if err := viper.ReadInConfig(); err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
		default:
			return err
		}
	} else if viper.GetString("format") == "default" {
		log.CliLogger.Infof("Using config file:", viper.ConfigFileUsed())
	}

	return nil
}
