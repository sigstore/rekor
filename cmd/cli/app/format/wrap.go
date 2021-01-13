package format

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"
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
		if s, ok := obj.(fmt.Stringer); ok {
			fmt.Print(s.String())
		} else {
			b, err := json.Marshal(obj)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(b))
		}
	}
}
