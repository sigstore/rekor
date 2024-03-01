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

package format

import (
	"encoding/json"
	"fmt"

	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"

	"github.com/sigstore/rekor/pkg/log"
	tleutils "github.com/sigstore/rekor/pkg/tle"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type CobraCmd func(cmd *cobra.Command, args []string)

type formatCmd func(args []string) (interface{}, error)

func WrapCmd(f formatCmd) CobraCmd {
	return func(_ *cobra.Command, args []string) {
		obj, err := f(args)
		if err != nil {
			log.CliLogger.Fatal(err)
		}

		// TODO: add flags to control output formatting (JSON, plaintext, etc.)
		format := viper.GetString("format")
		switch format {
		case "default":
			if s, ok := obj.(fmt.Stringer); ok {
				fmt.Print(s.String())
			} else {
				fmt.Println(toJSON(s))
			}
		case "json":
			fmt.Println(toJSON(obj))
		case "tle":
			if tle, ok := obj.(*rekor_pb.TransparencyLogEntry); ok {
				json, err := tleutils.MarshalTLEToJSON(tle)
				if err != nil {
					log.CliLogger.Fatalf("error converting to transparency log entry: %v", err)
				}
				fmt.Println(string(json))
			} else {
				log.CliLogger.Fatal("unable to print transparency log entry")
			}
		}
	}
}

func toJSON(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		log.CliLogger.Fatal(err)
	}
	return string(b)
}
