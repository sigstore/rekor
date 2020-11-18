package pkg

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/trillian"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/projectrekor/rekor/log"
)

type getProofResponse struct {
	Status string
	Proof  *trillian.GetInclusionProofByHashResponse
	Key    []byte
}

func DoGet(url string, rekorEntry []byte) {
	log := log.Logger
	// Set Context with Timeout for connects to thde log rpc server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := AddFileToRequest(request, bytes.NewReader(rekorEntry)); err != nil {
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

	resp := getProofResponse{}
	if err := json.Unmarshal(content, &resp); err != nil {
		log.Fatal(err)
	}

	pub, err := x509.ParsePKIXPublicKey(resp.Key)
	if err != nil {
		log.Fatal(err)
	}

	if resp.Proof != nil {
		leafHash := rfc6962.DefaultHasher.HashLeaf(rekorEntry)
		verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
		root, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, resp.Proof.SignedLogRoot)
		if err != nil {
			log.Fatal(err)
		}

		v := merkle.NewLogVerifier(rfc6962.DefaultHasher)
		proof := resp.Proof.Proof[0]
		if err := v.VerifyInclusionProof(proof.LeafIndex, int64(root.TreeSize), proof.Hashes, root.RootHash, leafHash); err != nil {
			log.Fatal(err)
		}
		log.Info("Proof correct!")
	} else {
		log.Info(resp.Status)
	}
}
