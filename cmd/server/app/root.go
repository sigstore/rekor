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
	"fmt"
	"os"

	"github.com/SigStore/rekor/pkg/log"
	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string
var logType string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rekor-server",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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

	rootCmd.PersistentFlags().String("trillian_log_server.address", "127.0.0.1", "Trillian log server address")
	rootCmd.PersistentFlags().Uint16("trillian_log_server.port", 8091, "Trillian log server port")
	rootCmd.PersistentFlags().String("rekor_server.address", "127.0.0.1", "Address to bind to")
	rootCmd.PersistentFlags().Uint16("rekor_server.port", 3000, "Port to bind to")

	rootCmd.PersistentFlags().Bool("enable_retrieve_api", true, "enables Redis-based index API endpoint")
	rootCmd.PersistentFlags().String("redis_server.address", "127.0.0.1", "Redis server address")
	rootCmd.PersistentFlags().Uint16("redis_server.port", 6379, "Redis server port")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
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
