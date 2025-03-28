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
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// addFlagToCmd adds the specified command of a specified type to the command's flag set
func addFlagToCmd(cmd *cobra.Command, required bool, flagType FlagType, flag, desc string) error {
	cmd.Flags().Var(NewFlagValue(flagType, ""), flag, desc)
	if required {
		return cmd.MarkFlagRequired(flag)
	}
	return nil
}

// addLogIndexFlag adds the "log-index" command to the command's flag set
func addLogIndexFlag(cmd *cobra.Command, required bool) error {
	return addFlagToCmd(cmd, required, logIndexFlag, "log-index", "the index of the entry in the transparency log")
}

// addUUIDPFlags adds the "uuid" command to the command's flag set
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
			fmt.Sprintf("format of the signature and/or public key; options = %v", pki.SupportedFormats()),
			false,
		},
		"public-key": {
			multiFileOrURLFlag,
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
		"aad": {
			base64Flag,
			"base64 encoded additional authenticated data",
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
	uuidGiven := uuidValid && viper.GetString("uuid") != ""
	indexGiven := indexValid && viper.GetString("log-index") != ""

	// if neither --entry or --artifact were given, then a reference to a uuid or index is needed
	if viper.GetString("entry") == "" && viper.GetString("artifact") == "" && viper.GetString("artifact-hash") == "" {
		if (uuidGiven && uuidValid) || (indexGiven && indexValid) {
			return nil
		}
		return errors.New("either 'entry' or 'artifact' or 'artifact-hash' must be specified")
	}

	return nil
}

func CreatePropsFromPflags() *types.ArtifactProperties {
	props := &types.ArtifactProperties{}

	artifactString := viper.GetString("artifact")
	if artifactString != "" {
		if isURL(artifactString) {
			props.ArtifactPath, _ = url.Parse(artifactString)
		} else {
			props.ArtifactPath = &url.URL{Path: artifactString}
		}
	}

	props.ArtifactHash = viper.GetString("artifact-hash")

	signatureString := viper.GetString("signature")
	if signatureString != "" {
		if isURL(signatureString) {
			props.SignaturePath, _ = url.Parse(signatureString)
		} else {
			props.SignaturePath = &url.URL{Path: signatureString}
		}
	}

	publicKeyString := viper.GetString("public-key")
	splitPubKeyString := strings.Split(publicKeyString, ",")
	if len(splitPubKeyString) > 0 {
		collectedKeys := []*url.URL{}
		for _, key := range splitPubKeyString {
			if isURL(key) {
				keyPath, _ := url.Parse(key)
				collectedKeys = append(collectedKeys, keyPath)
			} else {
				collectedKeys = append(collectedKeys, &url.URL{Path: key})
			}
		}
		props.PublicKeyPaths = collectedKeys
	}

	props.PKIFormat = viper.GetString("pki-format")
	b64aad := viper.GetString("aad")
	if b64aad != "" {
		props.AdditionalAuthenticatedData, _ = base64.StdEncoding.DecodeString(b64aad)
	}

	return props
}

// ParseTypeFlag validates the requested type (and optional version) are supported
func ParseTypeFlag(typeStr string) (string, string, error) {
	// typeStr can come in as:
	// type -> use default version for this kind
	// type:version_string -> attempt to use specified version string

	typeStrings := strings.SplitN(typeStr, ":", 2)
	tf, ok := types.TypeMap.Load(typeStrings[0])
	if !ok {
		return "", "", fmt.Errorf("unknown type %v", typeStrings[0])
	}
	ti := tf.(func() types.TypeImpl)()
	if ti == nil {
		return "", "", fmt.Errorf("type %v is not implemented", typeStrings[0])
	}

	switch len(typeStrings) {
	case 1:
		return typeStrings[0], "", nil
	case 2:
		if !ti.IsSupportedVersion(typeStrings[1]) {
			return "", "", fmt.Errorf("type %v does not support version %v", typeStrings[0], typeStrings[1])
		}
		return typeStrings[0], typeStrings[1], nil
	}
	return "", "", errors.New("malformed type string")
}
