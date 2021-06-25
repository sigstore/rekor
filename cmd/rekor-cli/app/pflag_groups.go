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
	"strings"

	"github.com/sigstore/rekor/pkg/pki/factory"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// addFlagToCmd adds the
func addFlagToCmd(cmd *cobra.Command, required bool, flagType FlagType, flag, desc string) error {
	cmd.Flags().Var(NewFlagValue(flagType, ""), flag, desc)
	if required {
		return cmd.MarkFlagRequired(flag)
	}
	return nil
}

func addLogIndexFlag(cmd *cobra.Command, required bool) error {
	return addFlagToCmd(cmd, required, logIndexFlag, "log-index", "the index of the entry in the transparency log")
}

func addUUIDPFlags(cmd *cobra.Command, required bool) error {
	return addFlagToCmd(cmd, required, uuidFlag, "uuid", "UUID of entry in transparency log (if known)")
}

func addArtifactPFlags(cmd *cobra.Command) error {
	flags := map[string]struct {
		flagType FlagType
		desc     string
		required bool
	}{
		"signature": {
			fileOrURLFlag,
			"path or URL to detached signature file",
			false,
		},
		"type": {
			typeFlag,
			fmt.Sprintf("type of entry expressed as type(:version)?; supported types = %v", types.ListImplementedTypes()),
			false,
		},
		"pki-format": {
			pkiFormatFlag,
			fmt.Sprintf("format of the signature and/or public key; options = %v", factory.SupportedFormats()),
			false,
		},
		"public-key": {
			fileOrURLFlag,
			"path or URL to public key file",
			false,
		},
		"artifact": {
			fileOrURLFlag,
			"path or URL to artifact file",
			false,
		},
		"artifact-hash": {
			shaFlag,
			"hex encoded SHA256 hash of artifact (when using URL)",
			false,
		},
		"entry": {
			fileOrURLFlag,
			"path or URL to pre-formatted entry file",
			false,
		},
	}

	for flag, flagVal := range flags {
		if err := addFlagToCmd(cmd, flagVal.required, flagVal.flagType, flag, flagVal.desc); err != nil {
			return err
		}
	}

	return nil
}

func validateArtifactPFlags(uuidValid, indexValid bool) error {
	uuidGiven := false
	if uuidValid && viper.GetString("uuid") != "" {
		uuidGiven = true
	}
	indexGiven := false
	if indexValid && viper.GetString("log-index") != "" {
		indexGiven = true
	}
	// we will need artifact, public-key, signature
	entry := viper.GetString("entry")
	if entry == "" && viper.GetString("artifact") == "" {
		if (uuidGiven && uuidValid) || (indexGiven && indexValid) {
			return nil
		}
		return errors.New("either 'entry' or 'artifact' must be specified")
	}

	typeStr := viper.GetString("type")
	signature := viper.GetString("signature")
	publicKey := viper.GetString("public-key")

	if entry == "" {
		if signature == "" && typeStr == "rekord" {
			return errors.New("--signature is required when --artifact is used")
		}
		if publicKey == "" && typeStr != "jar" && typeStr != "rfc3161" {
			return errors.New("--public-key is required when --artifact is used")
		}
	}

	return nil
}

func CreatePropsFromPflags() *types.ArtifactProperties {
	props := &types.ArtifactProperties{}

	artifactString := viper.GetString("artifact")
	if artifactString != "" {
		if IsURL(artifactString) {
			props.ArtifactPath, _ = url.Parse(artifactString)
		} else {
			props.ArtifactPath = &url.URL{Path: artifactString}
		}
	}

	props.ArtifactHash = viper.GetString("artifact-hash")

	signatureString := viper.GetString("signature")
	if signatureString != "" {
		if IsURL(signatureString) {
			props.SignaturePath, _ = url.Parse(signatureString)
		} else {
			props.SignaturePath = &url.URL{Path: signatureString}
		}
	}

	publicKeyString := viper.GetString("public-key")
	if publicKeyString != "" {
		if IsURL(publicKeyString) {
			props.PublicKeyPath, _ = url.Parse(publicKeyString)
		} else {
			props.PublicKeyPath = &url.URL{Path: publicKeyString}
		}
	}

	props.PKIFormat = viper.GetString("pki-format")

	return props
}

//TODO: add tests for this
func ParseTypeFlag(typeStr string) (string, string, error) {
	// typeStr can come in as:
	// type -> use default version for this kind
	// type:version_string -> attempt to use specified version string

	typeStrings := strings.SplitN(typeStr, ":", 2)
	if _, ok := types.TypeMap.Load(typeStrings[0]); !ok {
		return "", "", fmt.Errorf("unknown type %v", typeStrings[0])
	}

	switch len(typeStrings) {
	case 1:
		return typeStrings[0], "", nil
	case 2:
		return typeStrings[0], typeStrings[1], nil
	}
	return "", "", errors.New("malformed type string")
}
