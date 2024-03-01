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
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
)

type searchCmdOutput struct {
	UUIDs []string
}

func (s *searchCmdOutput) String() string {
	return strings.Join(s.UUIDs, "\n") + "\n" // one extra /n to terminate the list
}

func addSearchPFlags(cmd *cobra.Command) error {
	cmd.Flags().Var(NewFlagValue(pkiFormatFlag, ""), "pki-format", "format of the signature and/or public key")

	cmd.Flags().Var(NewFlagValue(fileOrURLFlag, ""), "public-key", "path or URL to public key file")

	cmd.Flags().Var(NewFlagValue(fileOrURLFlag, ""), "artifact", "path or URL to artifact file")

	cmd.Flags().Var(NewFlagValue(shaFlag, ""), "sha", "the SHA512, SHA256 or SHA1 sum of the artifact")

	cmd.Flags().Var(NewFlagValue(emailFlag, ""), "email", "email associated with the public key's subject")

	cmd.Flags().Var(NewFlagValue(operatorFlag, ""), "operator", "operator to use for the search. supported values are 'and' and 'or'")
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
	PreRun: func(cmd *cobra.Command, _ []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatalf("Error initializing cmd line args: %w", err)
		}
		if err := validateSearchPFlags(); err != nil {
			log.CliLogger.Error(err)
			_ = cmd.Help()
			os.Exit(1)
		}
	},
	Run: format.WrapCmd(func(_ []string) (interface{}, error) {
		log := log.CliLogger
		rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"), client.WithUserAgent(UserAgent()), client.WithRetryCount(viper.GetUint("retry")), client.WithLogger(log))
		if err != nil {
			return nil, err
		}

		params := index.NewSearchIndexParams()
		params.SetTimeout(viper.GetDuration("timeout"))
		params.Query = &models.SearchIndex{}

		artifactStr := viper.GetString("artifact")
		sha := viper.GetString("sha")
		if sha != "" {
			params.Query.Hash = util.PrefixSHA(sha)
		} else if artifactStr != "" {
			hasher := sha256.New()
			var tee io.Reader
			if isURL(artifactStr) {
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
			if _, err := io.ReadAll(tee); err != nil {
				return nil, fmt.Errorf("error processing '%v': %w", artifactStr, err)
			}

			hashVal := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
			params.Query.Hash = "sha256:" + hashVal
		}

		params.Query.Operator = viper.GetString("operator")

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
			case "tuf":
				params.Query.PublicKey.Format = swag.String(models.SearchIndexPublicKeyFormatTUF)
			default:
				return nil, fmt.Errorf("unknown pki-format %v", pkiFormat)
			}

			splitPubKeyString := strings.Split(publicKeyStr, ",")
			if len(splitPubKeyString) == 1 {
				if isURL(splitPubKeyString[0]) {
					params.Query.PublicKey.URL = strfmt.URI(splitPubKeyString[0])
				} else {
					keyBytes, err := os.ReadFile(filepath.Clean(splitPubKeyString[0]))
					if err != nil {
						return nil, fmt.Errorf("error reading public key file: %w", err)
					}
					params.Query.PublicKey.Content = strfmt.Base64(keyBytes)
				}
			} else {
				return nil, errors.New("only one public key must be provided")
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

		if len(resp.Payload) == 0 {
			return nil, fmt.Errorf("no matching entries found")
		}

		if viper.GetString("format") != "json" {
			fmt.Fprintln(os.Stderr, "Found matching entries (listed by UUID):")
		}

		return &searchCmdOutput{
			UUIDs: resp.GetPayload(),
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
