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
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/util"
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
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.rekor.yaml)")
	rootCmd.PersistentFlags().Bool("store_tree_state", true, "whether to store tree state in between invocations for additional verification")

	rootCmd.PersistentFlags().Var(&urlFlag{url: "https://rekor.sigstore.dev"}, "rekor_server", "Server address:port")
	rootCmd.PersistentFlags().Var(&formatFlag{format: "default"}, "format", "Command output format")

	rootCmd.PersistentFlags().String("api-key", "", "API key for rekor.sigstore.dev")

	// these are bound here and not in PreRun so that all child commands can use them
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
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
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	return nil
}

func GetRekorClient(rekorServerURL string) (*client.Rekor, error) {
	url, err := url.Parse(rekorServerURL)
	if err != nil {
		return nil, err
	}

	rt := httptransport.New(url.Host, client.DefaultBasePath, []string{url.Scheme})
	rt.Consumers["application/yaml"] = util.YamlConsumer()
	rt.Consumers["application/x-pem-file"] = runtime.TextConsumer()
	rt.Producers["application/yaml"] = util.YamlProducer()

	if viper.GetString("api-key") != "" {
		rt.DefaultAuthentication = httptransport.APIKeyAuth("apiKey", "query", viper.GetString("api-key"))
	}
	return client.New(rt, strfmt.Default), nil
}

type urlFlag struct {
	url string
}

func (u *urlFlag) String() string {
	return u.url
}

func (u *urlFlag) Set(s string) error {
	if s == "" {
		return errors.New("flag must be specified")
	}
	url, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if !url.IsAbs() {
		return fmt.Errorf("URL must be absolute, got %s", s)
	}
	lowercaseScheme := strings.ToLower(url.Scheme)
	if lowercaseScheme != "http" && lowercaseScheme != "https" {
		return fmt.Errorf("URL must be a valid HTTP or HTTPS URL, got %s", s)
	}
	u.url = s
	return nil
}

func (u *urlFlag) Type() string {
	return "url"
}

type formatFlag struct {
	format string
}

func (f *formatFlag) String() string {
	return f.format
}

func (f *formatFlag) Set(s string) error {
	choices := map[string]struct{}{"default": {}, "json": {}}
	if s == "" {
		f.format = "default"
		return nil
	}
	if _, ok := choices[s]; ok {
		f.format = s
		return nil
	}
	return fmt.Errorf("invalid flag value: %s, valid values are [default, json]", s)
}

func (f *formatFlag) Type() string {
	return "format"
}
