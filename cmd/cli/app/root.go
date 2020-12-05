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
package app

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "rekor",
	Short: "Rekor CLI",
	Long:  `Rekor command line interface tool`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rekor.yaml)")

	rootCmd.PersistentFlags().String("rekor_server", "http://localhost:3000", "Server address:port")

	rootCmd.PersistentFlags().String("rekord", "", "Rekor rekord file")

	rootCmd.PersistentFlags().String("signature", "", "Rekor signature")

	rootCmd.PersistentFlags().String("public-key", "", "Rekor publickey")

	rootCmd.PersistentFlags().String("artifact-path", "", "Rekor artifact path")

	rootCmd.PersistentFlags().String("artifact-url", "", "Rekor artifact url")

	rootCmd.PersistentFlags().String("artifact-sha", "", "Rekor artifact sha")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".rekor")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func validateRekorServerURL() error {
	rekorServerURL := viper.GetString("rekor_server")
	if rekorServerURL != "" {
		url, err := url.Parse(rekorServerURL)
		if err != nil {
			return fmt.Errorf("malformed rekor_server URL: %w", err)
		}
		if !url.IsAbs() {
			return errors.New("rekor_server URL must be absolute")
		}
		lowercaseScheme := strings.ToLower(url.Scheme)
		if lowercaseScheme != "http" && lowercaseScheme != "https" {
			return errors.New("rekor_server must be a valid HTTP or HTTPS URL")
		}
	} else {
		return errors.New("rekor_server must be specified")
	}
	return nil
}
