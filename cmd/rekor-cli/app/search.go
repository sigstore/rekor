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
	"errors"
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

func addSearchPFlags(cmd *cobra.Command) error {
	cmd.Flags().Var(NewFlagValue(pkiFormatFlag, ""), "pki-format", "format of the signature and/or public key")

	cmd.Flags().Var(NewFlagValue(fileOrURLFlag, ""), "public-key", "path or URL to public key file")

	cmd.Flags().Var(NewFlagValue(fileOrURLFlag, ""), "artifact", "path or URL to artifact file")

	cmd.Flags().Var(NewFlagValue(shaFlag, ""), "sha", "the SHA256 sum of the artifact")

	cmd.Flags().Var(NewFlagValue(emailFlag, ""), "email", "email associated with the public key's subject")
	return nil
}

func validateSearchPFlags() error {
	artifactStr := viper.GetString("artifact")

	publicKey := viper.GetString("public-key")
	sha := viper.GetString("sha")
	email := viper.GetString("email")

	if artifactStr == "" && publicKey == "" && sha == "" && email == "" {
		return errors.New("either 'sha' or 'artifact' or 'public-key' or 'email' must be specified")
	}
	if publicKey != "" {
		if viper.GetString("pki-format") == "" {
			return errors.New("pki-format must be specified if searching by public-key")
		}
	}
	return nil
}

// searchCmd represents the get command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Rekor search command",
	Long:  `Searches the Rekor index to find entries by sha, artifact,  public key, or e-mail`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateSearchPFlags(); err != nil {
			log.CliLogger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		log := log.CliLogger
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

			hasher := sha256.New()
			var tee io.Reader
			if IsURL(artifactStr) {
				/* #nosec G107 */
				resp, err := http.Get(artifactStr)
				if err != nil {
					return nil, fmt.Errorf("error fetching '%v': %w", artifactStr, err)
				}
				defer resp.Body.Close()
				tee = io.TeeReader(resp.Body, hasher)
			} else {
				file, err := os.Open(filepath.Clean(artifactStr))
				if err != nil {
					return nil, fmt.Errorf("error opening file '%v': %w", artifactStr, err)
				}
				defer func() {
					if err := file.Close(); err != nil {
						log.Error(err)
					}
				}()

				tee = io.TeeReader(file, hasher)
			}
			if _, err := ioutil.ReadAll(tee); err != nil {
				return nil, fmt.Errorf("error processing '%v': %w", artifactStr, err)
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
			publicKeyStr := viper.GetString("public-key")
			if IsURL(publicKeyStr) {
				params.Query.PublicKey.URL = strfmt.URI(publicKeyStr)
			} else {
				keyBytes, err := ioutil.ReadFile(filepath.Clean(publicKeyStr))
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
	initializePFlagMap()
	if err := addSearchPFlags(searchCmd); err != nil {
		log.CliLogger.Fatal("Error parsing cmd line args:", err)
	}

	rootCmd.AddCommand(searchCmd)
}
