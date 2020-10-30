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

// rekor upload --signature=acme.sig --public-key=acme.pub
// --artifact_url=https://acmeproject/acme123.tar.gz
// -- artifact_path acme123.tar.gz  (generate path)

/*
{
    "URL": "https://github.com/lukehinds/rekor-test-release/releases/download/0.1/rekor-cli",
    "SHA": "0ee27776da783ca7ab4f38659bfe76aee60a175acb07d1c1cb7256480c3bd762",
    "PublicKey": "LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptUUdOQkYrY0lNMEJEQUNhOEc3UkQydjNtaXdNdHhWYVppM0pCVnVlVkFxSEtDNGVLb01TNUhNQ1JvK0haVlJBCjcwWG1zVHBYMVoxZ1pRdXVDMEdEWTI2aEJoZWpBcTNoeDJydjYvOHE5MEJ2V0dIOXRWZUdwTDFzYUltNTJnRVIKWHlWZ2d6NWtBQzBTNnZNbjdkcjJldEJrV1dQK09qMDVTMDJZWkJUWWd4cE9ieWVjVVNjcUtOVGpzbFpRQkgyZApTSHVrM28yWjdoTTQ5VTBsN3piV3c0b0lUK2xBUmNzYWpRVHdXamxpYVBEL0hSalQyblJPaEloaXRlZC93Z3l6CnlkSXE1ZTZzMThWTGNUNzVxV25yWlhOUFdGd2YyNVJYWTN1dGtXK0dXNW5RZU44MFEya1JFZ2t4RnM1QWQ1V1oKdkU3dDgvaHg1em1zbFo0dGZGNHNpM1FaZUlRQmFjWWJ3eE1QU0RmOW9GR3hkR0ZUODg5d0pMR2dXbXIxVGtQTQpjTjA2d3hBUkd0eE4wejYxRkpUaWpMV1JialczdW5JOWhjUWNVbE4vUSsxNm90SHBlS1ZnNG9XMDBDcnZXT0Q2CnFrTGNNRDQ5eVVEOGZTR0IrUkVuaUJhODlDOWtRVTRTS2Rnc0xML1ErSksrU3k5S21JRHJtMWE0RGZQMXBzZmUKTGphcnpzVlpmS1VIZndjQUVRRUFBYlFpVEhWclpTQklhVzVrY3lBOGJHaHBibVJ6UUhCeWIzUnZibTFoYVd3dQpZMjl0UG9rQjFBUVRBUWdBUGhZaEJISUFsRnh1L0duWStvUmxDU2Ezd2FDZE9LUjZCUUpmbkNETkFoc0RCUWtECndtY0FCUXNKQ0FjQ0JoVUtDUWdMQWdRV0FnTUJBaDRCQWhlQUFBb0pFQ2Ezd2FDZE9LUjZaMWtMLzFJSzB2ZGUKWlg1cjVTZWJOeFRJTlNBQXZZa3JLUnlKNWY3bE9NOWdMR0l1YzJGb05VbmpWUVQwcklHOTAxOWg0OHBDeTkxZgpYakREUk1ZOWd6RldXQ2dHblhoMWhXSTNNN0JKRjZZRTZ1NkRYR3N2dVVwR3JOZVpBRzZra2F6QXVBbm5WMGtDCjA4em9SckFaQ3ZscGFacnlkOGl0YityVitRS3A3QXcybEFJSDFlNmR3TTRSTEZqdmZrOExKWHhqSkFvUG13NmwKTHcxOGM3b1c2UkxPOVFYUThlTTZyMnZISHBtMFR1ZHZaeWFmTnVDMzJHRGxNWTR1MFYxRGI4THN5bVBzQWh1QQoySno0L0tQcTZ1S3dJdG1WSzRwbmRmRUR1NkQxVG9vRFlYaXB0WWFmZHZVMzNwVVF4d0hvZlRUZkU1elp3MlBlCmxIM25aZHNnSFhHUHhKTExNcU9wVzRDL2NNNlpRVmdZU3RWcjBudlU2NitRalF2c2tVWlIwNmRkRXpuQnBHSnMKdHBtajlBZS9HUlk4RU5uTjkvMkdmRXVydHozZEtOVVpvak15MTUzamNHMFUxenpoMTE1V0o3dDh3SEJ1NFM0cAowZ0UrUkFxeXRBY0laRGQyTlNOcno4VnI5RkU5eCtmYXQ5RVJsYm5kQUJFNWlWOHNLMCtGYW5Xd2dia0JqUVJmCm5DRE5BUXdBdEJvdGhmY1J6cjN4cjNQOXA3UUNNd0t1aW9udk1DbThXZ3dOUzRDcGhxbzVOT3IyaU1qa0xQMEoKb21nSkxWWDVOK2Jydjh5NEg4cllQd0tCMTZvL2hBOEliR2JwWXltM0ZjeWtUd2NiV2J0UFRMRXRkQ1VQTFlURApOQzVMR0pwZzNlODZZZlF0QU42L01uWnlZT21sRHgyV0d0dExkbXNBU0dWdXg2QVZKcUl2K3gwNlVLSkVtSzN0CmpsRVZLeWcxMlJFenllNUlUNnFFU0dwT3pvMllsV1VxSVR3L0FhUFEyWnhVYXh2WUZvVU9jd2djZG5Ia2dzaEkKT245aC9OSFVtUDMyV1F2cWtRTXVVYVBJTlJzQzgzS3ZUREdseWZTSFZGek1hNGhETWhFY1h6NGFjaW5kNVdUZQp6eUxnWmhPYjdjTmVDeDR4Y3J0UEI2VTdCUi9GVkx6TEJsQXp1emppRWhZd0pvM0FPTXFGb1I1bUFxaGx1dE5PCnNzeW9mYnFUZ0diU0xkamJYUC9hRXRnejJNVjluL29jMVNCOEhlWk8vMTdKeWduenJ1SUt5Ky9sT1dPenQralYKVkZwVnloMXVlOGxGN3ltS1I0dHNsK2lJVmJxblB2cE1oTE9JQnFYRm4yZ01Da0dvSkx5N09IbzJXQUVKR2x0MwpTd3BicmpqMUFCRUJBQUdKQWJ3RUdBRUlBQ1lXSVFSeUFKUmNidnhwMlBxRVpRa210OEdnblRpa2VnVUNYNXdnCnpRSWJEQVVKQThKbkFBQUtDUkFtdDhHZ25UaWtlaW5pREFDRUFma1pxLzRScDJhTkE0ZGJvSjdVRlhET2FSa1YKOU1Lb0VaRnFUTU5vdkRMNXhoTWxnbFBQdS9sK2RoVGd4ZGVKOUVWSG9lenRiODk2VS9wT3VCUnNuOVZ0VzRZLwpqZWlXN0V5TlhBZC9PcnZuRmJ4KzdpWExxdXBaSkpGVGkvajlSaFZZTnNtbDdzZWJUUGVCbkdEQTkxcWJDNHhICnBRVkRDdWp4NjlWeE81RTFMU29oQ00rTy81dkxCbThpMW8vbmJGbWJ5N1ZDeUtlUkRmaHRmOW5DODRxc0U5R3EKVTcvTFNpazliZnhNV2JwcTh5a250bVMzYTBzemM0YlZGcGV6QnBtTmIwQVZjQitUbTlnV21FemhpTHM2RktBTgpJbnFOdVh1Qkw5UENhYzcrbVUrYzJtQmdHT1JHZDFkWk8zUkM4OXpGM3hCQlluQ09lNWNBTUZsYzFYR3NsbHNJCmR6ZHJkWHZiTkJ6L2o3MXB1TjhvRlltL1hiVmNpZU8wVGZRaURjVHQ4S2lpUjlUQUQ5L1A1OTNSTWxMT0dTOHAKaHZKYmlGb1pmWEhjbHNaRkhtOERRUWE5NElad1RCOG00Z0JWME0yWFN2ZEhvMzBsc3FqdFphWmlTclJoNHJzaApuMTRwYkFhVGRhS0VQY3Z0dWZiVXVXMElqWWQya3BJVC90Zz0KPU9naHIKLS0tLS1FTkQgUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLQo=",
    "Signature": "LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0tLS0KCmlRSEtCQUFCQ0FBMEZpRUVjZ0NVWEc3OGFkajZoR1VKSnJmQm9KMDRwSG9GQWwrY0tOTVdIR3hvYVc1a2MwQncKY205MGIyNXRZV2xzTG1OdmJRQUtDUkFtdDhHZ25UaWtlaXRmQy85T0w5OU5pSmNRUWRrc3ZlbW9WOFZCS09SSAp1MkJuM3lZZ01jOE9vS05uRmpEbG9HclEvUjhEVG4wRkRjR2lMQ0xFTytUWjJ3dUpvY0dXZktwRTFza0NrZXpuClJWNHE5cFZUem51YVl5ZjRpUmlmNEdVWllkQnl4eDVZS3kyTW8zeHV4NFRBZnAyY1N2ZTNJcGtmMnRlcVQwaGYKRGdCeGE4Uzl0cGZzNHJ0R05rWWhneUV4RVdiTFBzcFpTcDd6NFU0YytVbS9iamNNUEpUN1hVQ0praGtGUS9CdgpObDY2VGdBam5OMWhsQXhINXBJVnpscEFaaFczR2tveStDMVJsMGVGZHlaWTRySXN2N3FRZnp3NTU4cFZ4NHJlCloyL25ZNENPa3FoWVZEeGtDcmZHWWlNKzVvZEF1VVQvMEMrRDlzTjB1Ump1ckZrWUhmVGIxYWEwenVtNFJRMUoKZzk1R1RDNjhyY3lJTEVMWHhmM2pNYjduZDNvME1pbFJZVXgvTGttSXNML3dKeS9RSXYva0dISVNmbEVLeS9lbQpyMGtkeDBRUEw3V1hGdWp6cnU2b3NTNXAvbGM4enNQMDkwaGUxUmhFZ1prT0F0V2FwYXU5MEZoM3FsTlhiTW14CkNHYnovYThuUkZwNGVvNkQ2WkNFZGR4bnBxWDNQZHFKWE5IaVcrZz0KPUpuL2kKLS0tLS1FTkQgUEdQIFNJR05BVFVSRS0tLS0tCg=="
}
*/

/* GEt Public Key
gpg --export --armor "lhinds@protonmail.com" |base64  |tr -d '\n
*/

/* Sign
gpg --armor --output rekor-cli.asc --detach-sig rekor-cli
*/

package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/trillian"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/projectrekor/rekor-cli/app"
	"github.com/projectrekor/rekor-cli/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type RespStatusCode struct {
	Code string `json:"file_recieved"`
}

type getLeafResponse struct {
	Status RespStatusCode
	Leaf   *trillian.GetLeavesByIndexResponse
	Key    []byte
}

type RekorEntry struct {
	SHA       string `json:"SHA,omitempty"`
	URL       string `json:"URL,omitempty"`
	Signature []byte `json:"Signature"`
	PublicKey []byte `json:"PublicKey"`
}

type RekorArmorEntry struct {
	SHA       string `json:"SHA,omitempty"`
	URL       string `json:"URL,omitempty"`
	Signature string `json:"Signature"`
	PublicKey string `json:"PublicKey"`
}

func isArmorProtected(f *os.File) bool {
	_, err := armor.Decode(f)
	f.Seek(0, io.SeekStart)
	return err == nil
}

func hashGenerator(artifact string, fileObject []byte) string {
	log := log.Logger
	hasher := sha256.New()
	if strings.HasSuffix(artifact, ".gz") {
		log.Info("gzipped content detected")
		gz, err := gzip.NewReader(bytes.NewReader(fileObject))
		if err != nil {
			log.Error("Error:", err)
		}
		io.Copy(hasher, gz)
	} else {
		hasher.Write(fileObject)
	}
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha
}

func generateRekorFile(generatedSha string) string {
	log := log.Logger
	home, err := homedir.Dir()
	if err != nil {
		log.Error("Error finding Home Directory: ", err)
	}

	rekorDir := filepath.Join(home, ".rekor")

	if _, err := os.Stat(rekorDir); os.IsNotExist(err) {
		if err := os.Mkdir(rekorDir, 0755); err != nil {
			log.Error(".rekor directory creation failed: ", err)
		}
	}
	return filepath.Join(rekorDir, generatedSha+".txt")
}

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a rekord file",
	Long: `This command takes the public key, signature and URL
of the release artifact and uploads it to the rekor server.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := log.Logger
		rekorServer := viper.GetString("rekor_server")
		url := rekorServer + "/api/v1/add"
		signature := viper.GetString("signature")
		publicKey := viper.GetString("public-key")
		artifactURL := viper.GetString("artifact-url")

		// Before we download anything or validate the signing
		// Let's check the formatting is correct, if not we
		// exit and allow the user to resolve their corrupted
		// GPG files.
		sig, err := app.FormatSignature(signature)
		if err != nil {
			log.Error("Signature validation failed: ", err)
			os.Exit(1)
		}

		pub_key, err := app.FormatPubKey(publicKey)
		if err != nil {
			log.Error("Pubic key validation failed: ", err)
			os.Exit(1)
		}

		// Download the artifact set within flag artifactURL

		log.Info("Download artifact..")

		resp, err := http.DefaultClient.Get(artifactURL)
		if err != nil {
			log.Error(err)
		}

		defer resp.Body.Close()

		log.Info("Contents fetched..")

		readBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error("Error reading response body: ", err)
		}

		// Generate Hash for downloaded artifact
		generatedSha := hashGenerator(artifactURL, readBody)

		// Verify the artifact signing itself
		pubkeyRingReader, err := os.Open(publicKey)
		if err != nil {
			log.Error("Error opening publickey: ", err)
		}
		sigkeyRingReader, err := os.Open(signature)
		if err != nil {
			log.Error("Error opening signature: ", err)
		}

		var keyRing openpgp.EntityList
		if isArmorProtected(pubkeyRingReader) {
			keyRing, err = openpgp.ReadArmoredKeyRing(pubkeyRingReader)
		} else {
			keyRing, err = openpgp.ReadKeyRing(pubkeyRingReader)
		}

		dataReader := bytes.NewReader(readBody)

		if isArmorProtected(sigkeyRingReader) {
			_, err = openpgp.CheckArmoredDetachedSignature(keyRing, dataReader, sigkeyRingReader)
		} else {
			_, err = openpgp.CheckDetachedSignature(keyRing, dataReader, sigkeyRingReader)
		}
		if err != nil {
			log.Error("Signature Verification failed: ", err)
			os.Exit(1)
		}
		log.Info("Signature validation passed")

		// Generate a file name based off the artifact hash
		rekorFile := generateRekorFile(generatedSha)

		log.Info("Building rekor file : ", rekorFile)

		// Construct rekor json file
		// We need to approach this in two ways
		// as the public key and signature could be either
		// armored or binary
		if isArmorProtected(sigkeyRingReader) || isArmorProtected(sigkeyRingReader) {
			rekorArmorJSON := RekorArmorEntry{
				URL:       artifactURL,
				SHA:       generatedSha,
				Signature: sig,
				PublicKey: pub_key,
			}
			file, _ := json.MarshalIndent(rekorArmorJSON, "", " ")
			_ = ioutil.WriteFile(rekorFile, file, 0644)
		} else {
			pubKey, err := ioutil.ReadFile(publicKey)
			sigKey, err := ioutil.ReadFile(signature)
			if err != nil {
				log.Error("Error Loading: ", err)
			}
			rekorJSON := RekorEntry{
				URL:       artifactURL,
				SHA:       generatedSha,
				Signature: sigKey,
				PublicKey: pubKey,
			}
			file, _ := json.MarshalIndent(rekorJSON, "", " ")
			_ = ioutil.WriteFile(rekorFile, file, 0644)
		}

		// Upload to rekor
		log.Info("Uploading manifest to Rekor.")
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, "POST", url, nil)

		f, err := os.Open(rekorFile)
		if err != nil {
			log.Fatal(err)
		}

		if err := app.AddFileToRequest(request, f); err != nil {
			log.Fatal(err)
		}
		client := &http.Client{}
		response, err := client.Do(request)

		if err != nil {
			log.Fatal(err)
		}
		defer response.Body.Close()

		content, err := ioutil.ReadAll(response.Body)

		if err != nil {
			log.Fatal(err)
		}

		Leafresp := getLeafResponse{}

		if err := json.Unmarshal(content, &Leafresp); err != nil {
			log.Fatal(err)
		}

		log.Info("Status: ", Leafresp.Status)
	},
}

func init() {
	rootCmd.AddCommand(uploadCmd)
}
