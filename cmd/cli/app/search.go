/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-openapi/swag"

	"github.com/go-openapi/strfmt"

	"github.com/projectrekor/rekor/pkg/generated/client/index"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"github.com/projectrekor/rekor/pkg/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//TODO: unit tests for pflags
// searchCmd represents the get command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Rekor search command",
	Long:  `Searches the Rekor index to find entries by artifact or public key`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateSearchPFlags(); err != nil {
			log.Logger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			log.Fatal(err)
		}

		params := index.NewSearchIndexParams()
		params.Query = &models.SearchIndex{}

		artifactStr := viper.GetString("artifact")
		sha := viper.GetString("sha")
		if sha != "" {
			params.Query.Hash = sha
		} else if artifactStr != "" {
			artifact := fileOrURLFlag{}
			if err := artifact.Set(artifactStr); err != nil {
				log.Fatal(err)
			}

			hasher := sha256.New()
			var tee io.Reader
			if artifact.IsURL {
				/* #nosec G107 */
				resp, err := http.Get(artifact.String())
				if err != nil {
					log.Fatal(fmt.Errorf("error fetching '%v': %w", artifact.String(), err))
				}
				defer resp.Body.Close()
				tee = io.TeeReader(resp.Body, hasher)
			} else {
				file, err := os.Open(filepath.Clean(artifact.String()))
				if err != nil {
					log.Fatal(fmt.Errorf("error opening file '%v': %w", artifact.String(), err))
				}
				defer func() {
					if err := file.Close(); err != nil {
						log.Error(err)
					}
				}()

				tee = io.TeeReader(file, hasher)
			}
			if _, err := ioutil.ReadAll(tee); err != nil {
				log.Fatal(fmt.Errorf("error processing '%v': %w", artifact.String(), err))
			}

			hashVal := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
			params.Query.Hash = hashVal
		}

		publicKeyStr := viper.GetString("public-key")
		if publicKeyStr != "" {
			params.Query.PublicKey = &models.SearchIndexPublicKey{}
			pkiFormat := viper.GetString("pki-format")
			switch pkiFormat {
			case "pgp":
				params.Query.PublicKey.Format = swag.String(models.SearchIndexPublicKeyFormatPgp)
			case "minisign":
				params.Query.PublicKey.Format = swag.String(models.SearchIndexPublicKeyFormatMinisign)
			case "x509":
				params.Query.PublicKey.Format = swag.String(models.SearchIndexPublicKeyFormatX509)
			default:
				log.Fatal(fmt.Errorf("unknown pki-format %v", pkiFormat))
			}
			publicKey := fileOrURLFlag{}
			if err := publicKey.Set(publicKeyStr); err != nil {
				log.Fatal(err)
			}
			if publicKey.IsURL {
				params.Query.PublicKey.URL = strfmt.URI(publicKey.String())
			} else {
				keyBytes, err := ioutil.ReadFile(filepath.Clean(publicKey.String()))
				if err != nil {
					log.Fatal(fmt.Errorf("error reading public key file: %w", err))
				}
				params.Query.PublicKey.Content = strfmt.Base64(keyBytes)
			}
		}

		resp, err := rekorClient.Index.SearchIndex(params)
		if err != nil {
			switch err.(type) {
			case *index.SearchIndexDefault:
				if err.(*index.SearchIndexDefault).Code() == http.StatusNotImplemented {
					fmt.Printf("Search index not enabled on %v\n", viper.GetString("rekor_server"))
					return
				}
			default:
				log.Fatal(err)
			}
		}

		for i, val := range resp.GetPayload() {
			if i == 0 {
				fmt.Println("Found matching entries (listed by UUID):")
			}
			fmt.Println(val)
		}
	},
}

func init() {
	if err := addSearchPFlags(searchCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(searchCmd)
}
