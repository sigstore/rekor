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
	"io/ioutil"
	"os"
	"time"

	"github.com/google/trillian"
	"github.com/lukehinds/rekor/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

//type LeafData struct {
//	File string `json:"file"`
//	Hash string `json:"hash"`
//}

//type LeafData struct {
//	Signatures []struct {
//		Keyid string `json:"keyid"`
//		Sig   string `json:"sig"`
//	} `json:"signatures"`
//	Signed struct {
//		Type       string `json:"_type"`
//		Byproducts struct {
//			ReturnValue int    `json:"return-value"`
//			Stderr      string `json:"stderr"`
//			Stdout      string `json:"stdout"`
//		} `json:"byproducts"`
//		Command     []string `json:"command"`
//		Environment struct {
//		} `json:"environment"`
//		Materials struct {
//			FooPy struct {
//				Sha256 string `json:"sha256"`
//			} `json:"foo.py"`
//		} `json:"materials"`
//		Name     string `json:"name"`
//		Products struct {
//			FooTarGz struct {
//				Sha256 string `json:"sha256"`
//			} `json:"foo.tar.gz"`
//		} `json:"products"`
//	} `json:"signed"`
//}

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Rekor CLI",
	Long: `Rekor interacts with a transparency log

For more information, visit [domain]`,

	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		logRpcServer := viper.GetString("log_rpc_server")
		tLogID := viper.GetInt64("tlog_id")
		linkfile := viper.GetString("linkfile")

		// Set Context with Timeout for connects to thde log rpc server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Set up and test connection to rpc server
		conn, err := grpc.DialContext(ctx, logRpcServer, grpc.WithInsecure())
		if err != nil {
			log.Error("Failed to connect to log server:", err)
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

		resp, err = server.addLeaf(byteValue, tLogID)
		log.Infof("Server PUT Response: %s", resp.status)
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
