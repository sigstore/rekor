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
	"bytes"
	"crypto"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/x509tools"
	"github.com/sigstore/rekor/cmd/rekor-cli/app/format"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/timestamp"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type fileFlag struct {
	value string
}

func (f *fileFlag) String() string {
	return f.value
}

func (f *fileFlag) Set(s string) error {
	if s == "" {
		return errors.New("flag must be specified")
	}
	if _, err := os.Stat(filepath.Clean(s)); os.IsNotExist(err) {
		return err
	}
	f.value = s
	return nil
}

func (f *fileFlag) Type() string {
	return "fileFlag"
}

type oidFlag struct {
	value asn1.ObjectIdentifier
}

func (f *oidFlag) String() string {
	return f.value.String()
}

func (f *oidFlag) Set(s string) error {
	parts := strings.Split(s, ".")
	f.value = make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return errors.New("error parsing OID")
		}
		f.value[i] = num
	}
	return nil
}

func (f *oidFlag) Type() string {
	return "oidFlag"
}

func addTimestampFlags(cmd *cobra.Command) error {
	cmd.Flags().Var(&fileFlag{}, "artifact", "path to an artifact to timestamp")
	cmd.Flags().Var(&uuidFlag{}, "artifact-hash", "hex encoded SHA256 hash of the the artifact to timestamp")
	cmd.Flags().Bool("nonce", true, "specify a pseudo-random nonce in the request")
	cmd.Flags().Var(&oidFlag{}, "tsa-policy", "optional dotted OID notation for the policy that the TSA should use to create the response")

	cmd.Flags().String("out", "response.tsr", "path to a file to write response.")

	// TODO: Add a flag to indicate a JSON formatted timestamp request/response.
	return nil
}

func validateTimestampFlags() error {
	artifactStr := viper.GetString("artifact")
	digestStr := viper.GetString("artifact-hash")

	if artifactStr == "" && digestStr == "" {
		return errors.New("artifact or hash to timestamp must be specified")
	}

	if digestStr != "" {
		digest := uuidFlag{}
		if err := digest.Set(digestStr); err != nil {
			return err
		}
	}

	policyStr := viper.GetString("tsa-policy")
	if policyStr != "" {
		oid := oidFlag{}
		if err := oid.Set(policyStr); err != nil {
			return err
		}
	}

	return nil
}

func createRequestFromFlags() (*pkcs9.TimeStampReq, error) {
	var timestampReq *pkcs9.TimeStampReq
	digestStr := viper.GetString("artifact-hash")
	policyStr := viper.GetString("tsa-policy")

	opts := util.TimestampRequestOptions{
		// Always use a SHA256 right now.
		Hash: crypto.SHA256,
	}
	if policyStr != "" {
		oid := oidFlag{}
		if err := oid.Set(policyStr); err != nil {
			return nil, err
		}
		opts.TSAPolicyOid = oid.value
	}
	if viper.GetBool("nonce") {
		opts.Nonce = x509tools.MakeSerial()
	}

	var digest []byte
	if digestStr != "" {
		decoded, err := hex.DecodeString(digestStr)
		if err != nil {
			return nil, err
		}
		digest = decoded
	}
	if digestStr == "" {
		artifactStr := viper.GetString("artifact")
		artifactBytes, err := ioutil.ReadFile(filepath.Clean(artifactStr))
		if err != nil {
			return nil, fmt.Errorf("error reading request from file: %w", err)
		}
		h := opts.Hash.New()
		if _, err := h.Write(artifactBytes); err != nil {
			return nil, err
		}
		digest = h.Sum(nil)
	}

	timestampReq, err := util.TimestampRequestFromDigest(digest, opts)
	if err != nil {
		return nil, fmt.Errorf("error creating timestamp request: %w", err)
	}

	return timestampReq, nil
}

type timestampCmdOutput struct {
	Timestamp time.Time
	Location  string
	UUID      string
	Index     int64
}

func (t *timestampCmdOutput) String() string {
	return fmt.Sprintf("Artifact timestamped at %s\nWrote timestamp response to %v\nCreated entry at index %d, available at: %v%v\n",
		t.Timestamp, t.Location, t.Index, viper.GetString("rekor_server"), t.UUID)
}

var timestampCmd = &cobra.Command{
	Use:   "timestamp",
	Short: "Rekor timestamp command",
	Long:  "Generates and uploads (WIP) an RFC 3161 timestamp response to the log. The timestamp response can be verified locally using Rekor's timestamping cert chain.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateTimestampFlags(); err != nil {
			log.Logger.Error(err)
			_ = cmd.Help()
			return err
		}
		return nil
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		rekorClient, err := client.GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}

		timestampReq, err := createRequestFromFlags()
		if err != nil {
			return nil, err
		}
		requestBytes, err := asn1.Marshal(*timestampReq)
		if err != nil {
			return nil, err
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.Request = ioutil.NopCloser(bytes.NewReader(requestBytes))

		var respBytes bytes.Buffer
		resp, err := rekorClient.Timestamp.GetTimestampResponse(params, &respBytes)
		if err != nil {
			return nil, err
		}
		// Sanity check response and check if the TimeStampToken was successfully created
		psd, err := timestampReq.ParseResponse(respBytes.Bytes())
		if err != nil {
			return nil, err
		}
		genTime, err := util.GetSigningTime(psd)
		if err != nil {
			return nil, err
		}

		// Write response to file
		outStr := viper.GetString("out")
		if outStr == "" {
			outStr = "response.tsr"
		}
		if err := ioutil.WriteFile(outStr, respBytes.Bytes(), 0600); err != nil {
			return nil, err
		}

		return &timestampCmdOutput{
			Location:  outStr,
			UUID:      string(resp.Location),
			Timestamp: genTime.Round(time.Second),
			Index:     resp.Index,
		}, nil
	}),
}

func init() {
	if err := addTimestampFlags(timestampCmd); err != nil {
		log.Logger.Fatal("Error parsing cmd line args: ", err)
	}

	rootCmd.AddCommand(timestampCmd)
}
