/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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

	"github.com/sigstore/rekor/cmd/cli/app/format"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type logProofOutput struct {
	RootHash string
	Hashes   []string
}

func (l *logProofOutput) String() string {
	s := fmt.Sprintf("Current Root Hash: %v\n", l.RootHash)
	s += "Hashes: ["
	for i, hash := range l.Hashes {
		if i+1 == len(l.Hashes) {
			s += hash
		} else {
			s += fmt.Sprintf("%v,", hash)
		}
	}
	s += "]\n"
	return s
}

// logProof represents the consistency proof
var logProofCmd = &cobra.Command{
	Use:   "logproof",
	Short: "Rekor logproof command",
	Long:  `Prints information required to compute the consistency proof of the transparency log`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
		if viper.GetUint64("first-size") > viper.GetUint64("last-size") {
			log.Logger.Error("last-size must be >= to first-size")
			os.Exit(1)
		}
		if viper.GetUint64("first-size") == 0 {
			log.Logger.Error("first-size must be > 0")
			os.Exit(1)
		}
		if viper.GetUint64("last-size") == 0 {
			log.Logger.Error("last-size must be > 0")
			os.Exit(1)
		}
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		rekorClient, err := GetRekorClient(viper.GetString("rekor_server"))
		if err != nil {
			return nil, err
		}

		firstSize := int64(viper.GetUint64("first-size"))
		lastSize := int64(viper.GetUint64("last-size"))

		params := tlog.NewGetLogProofParams()
		params.FirstSize = &firstSize
		params.LastSize = lastSize

		result, err := rekorClient.Tlog.GetLogProof(params)
		if err != nil {
			return nil, err
		}

		consistencyProof := result.GetPayload()
		return &logProofOutput{
			RootHash: *consistencyProof.RootHash,
			Hashes:   consistencyProof.Hashes,
		}, nil
	}),
}

func init() {
	logProofCmd.Flags().Uint64("first-size", 1, "the size of the log where the proof should begin")
	logProofCmd.Flags().Uint64("last-size", 1, "the size of the log where the proof should end")
	if err := logProofCmd.MarkFlagRequired("last-size"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rootCmd.AddCommand(logProofCmd)
}
