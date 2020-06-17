/*
Copyright © 2020 Luke Hinds <lhinds@redhat.com>

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
package cmd

import (
	"context"
	"fmt"
	"github.com/google/trillian"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Rekor CLI",
	Long: `Rekor interacts with a transparency log

For more information, visit [domain]`,
	Run: func(cmd *cobra.Command, args []string) {
		logRpcServer := viper.GetString("log_rpc_server")
		tLogID := viper.GetInt64("tlog_id")
		linkfile := viper.GetString("linkfile")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := grpc.DialContext(ctx, logRpcServer, grpc.WithInsecure())
		if err != nil {
			fmt.Println("Failed to connect to log server:", err)
		}
		defer conn.Close()

		jsonFile, err := os.Open(linkfile)
		if err != nil {
			fmt.Println(err)
		}
		byteValue, _ := ioutil.ReadAll(jsonFile)
		defer jsonFile.Close()

		tLogClient := trillian.NewTrillianLogClient(conn)
		server := serverInstance(tLogClient, tLogID)

		resp := &Response{}
		resp, err =  server.getLeaf(byteValue, tLogID)
		log.Printf("Server GET Response: %s", resp.status)
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
