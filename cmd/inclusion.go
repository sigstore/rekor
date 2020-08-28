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
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/spf13/cobra"
)

// inclusionCmd represents the inclusion command
var inclusionCmd = &cobra.Command{
	Use:   "inclusion",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("inclusion called")
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

		c1 := context.Background()
		c1, cancel = context.WithCancel(c1)
		defer cancel()

		err = server.verifyInclusion(c1, byteValue, tLogID)
		log.Printf("Server GET Response: %s", resp.status)
	},
}

func init() {
	rootCmd.AddCommand(inclusionCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// inclusionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// inclusionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
