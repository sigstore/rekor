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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	_ "gocloud.dev/blob/fileblob" // fileblob
	_ "gocloud.dev/blob/gcsblob"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gocloud.dev/blob"

	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/util"
)

const rekorSthBucketEnv = "REKOR_STH_BUCKET"

// watchCmd represents the serve command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start a process to watch and record STH's from Rekor",
	Long:  `Start a process to watch and record STH's from Rekor`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		// Setup the logger to dev/prod
		log.ConfigureLogger(viper.GetString("log_type"))

		// workaround for https://github.com/sigstore/rekor/issues/68
		// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
		_ = flag.CommandLine.Parse([]string{})

		host := viper.GetString("rekor_server.address")
		port := viper.GetUint("rekor_server.port")
		interval := viper.GetDuration("interval")
		url := fmt.Sprintf("http://%s:%d", host, port)
		c, err := app.GetRekorClient(url)
		if err != nil {
			return err
		}

		keyResp, err := c.Pubkey.GetPublicKey(nil)
		if err != nil {
			return err
		}
		publicKey := keyResp.Payload
		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			return errors.New("failed to decode public key of server")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}

		ctx := context.Background()
		bucketURL := os.Getenv(rekorSthBucketEnv)
		if bucketURL == "" {
			log.CliLogger.Fatalf("%s env var must be set", rekorSthBucketEnv)
		}
		bucket, err := blob.OpenBucket(ctx, bucketURL)
		if err != nil {
			return err
		}
		defer bucket.Close()
		tick := time.NewTicker(interval)
		var last *SignedAndUnsignedLogRoot

		for {
			<-tick.C
			log.Logger.Info("performing check")
			lr, err := doCheck(c, pub)
			if err != nil {
				log.Logger.Warnf("error verifiying tree: %s", err)
				continue
			}
			log.Logger.Infof("Found and verified state at %d", lr.VerifiedLogRoot.Size)
			if last != nil && last.VerifiedLogRoot.Size == lr.VerifiedLogRoot.Size {
				log.Logger.Infof("Last tree size is the same as the current one: %d %d",
					last.VerifiedLogRoot.Size, lr.VerifiedLogRoot.Size)
				// If it's the same, it shouldn't have changed but we'll still upload anyway
				// in case that failed.
			}

			if err := uploadToBlobStorage(ctx, bucket, lr); err != nil {
				log.Logger.Warnf("error uploading result: %s", err)
				continue
			}
			last = lr
		}
	},
}

func init() {
	watchCmd.Flags().Duration("interval", 1*time.Minute, "Polling interval")
	rootCmd.AddCommand(watchCmd)
}

func doCheck(c *client.Rekor, pub crypto.PublicKey) (*SignedAndUnsignedLogRoot, error) {
	li, err := c.Tlog.GetLogInfo(nil)
	if err != nil {
		return nil, errors.Wrap(err, "getting log info")
	}
	sth := util.RekorSTH{}
	if err := sth.UnmarshalText([]byte(*li.Payload.SignedTreeHead)); err != nil {
		return nil, errors.Wrap(err, "unmarshalling tree head")
	}

	if !sth.Verify(pub) {
		return nil, errors.Wrap(err, "signed tree head failed verification")
	}

	return &SignedAndUnsignedLogRoot{
		VerifiedLogRoot: &sth,
	}, nil
}

func uploadToBlobStorage(ctx context.Context, bucket *blob.Bucket, lr *SignedAndUnsignedLogRoot) error {
	b, err := json.Marshal(lr)
	if err != nil {
		return err
	}

	objName := fmt.Sprintf("sth-%d.json", lr.VerifiedLogRoot.Size)
	w, err := bucket.NewWriter(ctx, objName, nil)
	if err != nil {
		return err
	}
	defer w.Close()
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

// For JSON marshalling
type SignedAndUnsignedLogRoot struct {
	VerifiedLogRoot *util.RekorSTH
}
