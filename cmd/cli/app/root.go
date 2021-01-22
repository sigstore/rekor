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

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/projectrekor/rekor/pkg/generated/client"
	"github.com/projectrekor/rekor/pkg/util"
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

//Execute runs the base CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rekor.yaml)")

	rootCmd.PersistentFlags().Var(&urlFlag{url: "https://api.rekor.dev"}, "rekor_server", "Server address:port")
	rootCmd.PersistentFlags().Var(&formatFlag{format: "default"}, "format", "Command output format")

	// these are bound here and not in PreRun so that all child commands can use them
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
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

	viper.SetEnvPrefix("rekor")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
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

func (u *formatFlag) Type() string {
	return "format"
}
