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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectrekor/rekor/pkg/types"
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

	rootCmd.PersistentFlags().String("rekor_server", "http://localhost:3000", "Server address:port")

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

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func addArtifactPFlags(cmd *cobra.Command) error {
	cmd.Flags().String("signature", "", "path to detached signature file")
	if err := cmd.MarkFlagFilename("signature"); err != nil {
		return err
	}

	cmd.Flags().String("public-key", "", "path to public key file")
	if err := cmd.MarkFlagFilename("public-key"); err != nil {
		return err
	}

	cmd.Flags().String("artifact", "", "path or URL to artifact file")

	cmd.Flags().String("rekord", "", "Rekor rekord file")
	if err := cmd.MarkFlagFilename("rekord"); err != nil {
		return err
	}

	cmd.Flags().String("sha", "", "the sha of the artifact")
	return nil
}

func validateArtifactPFlags() error {
	rekord := viper.GetString("rekord")
	if rekord != "" {
		if _, err := os.Stat(filepath.Clean(rekord)); os.IsNotExist(err) {
			return fmt.Errorf("error processing 'rekord' file: %w", err)
		}
	} else {
		// we will need artifact, public-key, signature, and potentially SHA
		artifact := viper.GetString("artifact")
		if artifact == "" {
			return errors.New("either 'rekord' or 'artifact' must be specified")
		}

		sha := viper.GetString("sha")
		if sha != "" {
			if _, err := hex.DecodeString(sha); (err != nil) || (len(sha) != 64) {
				if err == nil {
					err = errors.New("invalid length for SHA256 hash value")
				}
				return fmt.Errorf("SHA value specified is invalid: %w", err)
			}
		}

		if _, err := os.Stat(filepath.Clean(artifact)); os.IsNotExist(err) {
			url, err := url.Parse(artifact)
			if err == nil && url.IsAbs() {
				if sha == "" {
					return errors.New("a valid SHA hash must be specified when specifying a URL for 'artifact'")
				}
			} else {
				return errors.New("artifact must be a valid URL or path to a file")
			}
		}

		var err error
		signature := viper.GetString("signature")
		if signature != "" {
			if _, err = os.Stat(filepath.Clean(signature)); os.IsNotExist(err) {
				return fmt.Errorf("error reading signature file: %w", err)
			}
		} else {
			return errors.New("signature flag is required when --artifact is used")
		}

		publicKey := viper.GetString("public-key")
		if publicKey != "" {
			if _, err = os.Stat(filepath.Clean(publicKey)); os.IsNotExist(err) {
				return fmt.Errorf("error reading public key: %w", err)
			}
		} else {
			return errors.New("public-key flag is required when --artifact is used")
		}
	}
	return nil
}

func buildRekorEntryFromPFlags() (*types.RekorEntry, error) {
	// if rekord is specified, ensure it is a valid path and we can open it
	var rekorEntry types.RekorEntry

	rekord := viper.GetString("rekord")
	if rekord != "" {
		rekordBytes, err := ioutil.ReadFile(filepath.Clean(rekord))
		if err != nil {
			return nil, fmt.Errorf("error processing 'rekord' file: %w", err)
		}
		if err := json.Unmarshal(rekordBytes, &rekorEntry); err != nil {
			return nil, fmt.Errorf("error parsing rekord file: %w", err)
		}
	} else {
		// we will need artifact, public-key, signature, and potentially SHA
		artifact := viper.GetString("artifact")
		url, err := url.Parse(artifact)
		if err == nil && url.IsAbs() {
			rekorEntry.URL = artifact
			rekorEntry.SHA = viper.GetString("sha")
		} else {
			artifactBytes, err := ioutil.ReadFile(filepath.Clean(artifact))
			if err != nil {
				return nil, fmt.Errorf("error reading artifact file: %w", err)
			}
			rekorEntry.Data = artifactBytes
		}

		signature := viper.GetString("signature")
		rekorEntry.Signature, err = ioutil.ReadFile(filepath.Clean(signature))
		if err != nil {
			return nil, fmt.Errorf("error reading signature file: %w", err)
		}

		publicKey := viper.GetString("public-key")
		rekorEntry.PublicKey, err = ioutil.ReadFile(filepath.Clean(publicKey))
		if err != nil {
			return nil, fmt.Errorf("error reading public key: %w", err)
		}
	}

	if err := rekorEntry.Load(context.Background()); err != nil {
		return nil, fmt.Errorf("error loading entry: %w", err)
	}
	return &rekorEntry, nil
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
