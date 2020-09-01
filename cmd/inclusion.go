/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

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
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/google/trillian"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

// inclusionCmd represents the inclusion command
var inclusionCmd = &cobra.Command{
	Use:   "inclusion",
	Short: "Rekor CLI",
	Long: `Rekor interacts with a transparency log

For more information, visit [domain]`,
	Run: func(cmd *cobra.Command, args []string) {
		logRpcServer := viper.GetString("log_rpc_server")
		tLogID := viper.GetInt64("tlog_id")
		linkfile := viper.GetString("linkfile")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Set up and test connection to rpc server
		conn, err := grpc.DialContext(ctx, logRpcServer, grpc.WithInsecure())
		if err != nil {
			fmt.Println("Failed to connect to log server:", err)
		}
		defer conn.Close()

		jsonFile, err := os.Open(linkfile)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		byteValue, _ := ioutil.ReadAll(jsonFile)
		defer jsonFile.Close()

		tLogClient := trillian.NewTrillianLogClient(conn)
		server := serverInstance(tLogClient, tLogID)

		resp := &Response{}

		resp, err = server.getInclusion(byteValue, tLogID)
		log.Printf("Server PUT Response: %s", resp)
	},
}

func init() {
	rootCmd.AddCommand(inclusionCmd)
}
