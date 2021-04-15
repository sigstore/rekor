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
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type cobraCmd func(cmd *cobra.Command, args []string)

type formatCmd func(args []string) (interface{}, error)

func WrapCmd(f formatCmd) cobraCmd {
	return func(cmd *cobra.Command, args []string) {
		obj, err := f(args)
		if err != nil {
			log.Fatal(err)
		}

		// TODO: add flags to control output formatting (JSON, plaintext, etc.)
		format := viper.GetString("format")
		switch format {
		case "default":
			if s, ok := obj.(fmt.Stringer); ok {
				fmt.Print(s.String())
			} else {
				fmt.Println(toJson(s))
			}
		case "json":
			fmt.Println(toJson(obj))
		}
	}
}

func toJson(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}
