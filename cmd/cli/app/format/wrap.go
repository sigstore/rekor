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
