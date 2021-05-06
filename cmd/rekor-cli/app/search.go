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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
)

type searchCmdOutput struct {
	uuids []string
}

func (s *searchCmdOutput) String() string {
	str := "No matching entries were found\n"
	for i, uuid := range s.uuids {
		if i == 0 {
			str = "Found matching entries (listed by UUID):\n"
		}
		str += fmt.Sprintf("%v\n", uuid)
	}
	return str
}

// searchCmd represents the get command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Rekor search command",
	Long:  `Searches the Rekor index to find entries by sha, artifact,  public key, or e-mail`,
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
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		log := log.Logger
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
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
				return nil, err
			}

			hasher := sha256.New()
			var tee io.Reader
			if artifact.IsURL {
				/* #nosec G107 */
				resp, err := http.Get(artifact.String())
				if err != nil {
					return nil, fmt.Errorf("error fetching '%v': %w", artifact.String(), err)
				}
				defer resp.Body.Close()
				tee = io.TeeReader(resp.Body, hasher)
			} else {
				file, err := os.Open(filepath.Clean(artifact.String()))
				if err != nil {
					return nil, fmt.Errorf("error opening file '%v': %w", artifact.String(), err)
				}
				defer func() {
					if err := file.Close(); err != nil {
						log.Error(err)
					}
				}()

				tee = io.TeeReader(file, hasher)
			}
			if _, err := ioutil.ReadAll(tee); err != nil {
				return nil, fmt.Errorf("error processing '%v': %w", artifact.String(), err)
			}

			hashVal := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
			params.Query.Hash = "sha256:" + hashVal
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
			case "ssh":
				params.Query.PublicKey.Format = swag.String(models.SearchIndexPublicKeyFormatSSH)
			default:
				return nil, fmt.Errorf("unknown pki-format %v", pkiFormat)
			}
			publicKey := fileOrURLFlag{}
			if err := publicKey.Set(publicKeyStr); err != nil {
				return nil, err
			}
			if publicKey.IsURL {
				params.Query.PublicKey.URL = strfmt.URI(publicKey.String())
			} else {
				keyBytes, err := ioutil.ReadFile(filepath.Clean(publicKey.String()))
				if err != nil {
					return nil, fmt.Errorf("error reading public key file: %w", err)
				}
				params.Query.PublicKey.Content = strfmt.Base64(keyBytes)
			}
		}

		emailStr := viper.GetString("email")
		if emailStr != "" {
			params.Query.Email = strfmt.Email(emailStr)
		}
		resp, err := rekorClient.Index.SearchIndex(params)
		if err != nil {
			switch t := err.(type) {
			case *index.SearchIndexDefault:
				if t.Code() == http.StatusNotImplemented {
					return nil, fmt.Errorf("search index not enabled on %v", viper.GetString("rekor_server"))
				}
				return nil, err
			default:
				return nil, err
			}
		}

		return &searchCmdOutput{
			uuids: resp.GetPayload(),
		}, nil
	}),
}

func init() {
	if err := addSearchPFlags(searchCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(searchCmd)
}
