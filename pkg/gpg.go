package pkg

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func FormatPubKey(pubkeyFilePath string) (string, error) {
	pubKey, err := ioutil.ReadFile(pubkeyFilePath)

	if err != nil {
		return "Error opening File: ", err
	}

	if strings.Contains(string(pubKey), "-----BEGIN PGP") {
		buf := bytes.NewReader(pubKey)

		block, err := armor.Decode(buf)

		if err != nil {
			return "Error Decoding: ", err
		}

		if block.Type == "PGP PUBLIC KEY BLOCK" {
			reader := packet.NewReader(block.Body)
			pkt, err := reader.Next()
			if err != nil {
				return "Error reading file: ", err
			}

			_, ok := pkt.(*packet.PublicKey)
			if !ok {
				return ("Invalid Public Key"), err
			}
		}
		base64string := base64.StdEncoding.EncodeToString(pubKey)
		return base64string, nil

	} else {
		// It's likely a binary file
		pack, err := packet.Read(bytes.NewReader(pubKey))
		if err != nil {
			return "Error reading pub key", err
		}

		// Was it really a public key file ? If yes, get the PublicKey
		_, ok := pack.(*packet.PublicKey)
		if !ok {
			return "Invalid public key.", err
		}
		base64string := base64.StdEncoding.EncodeToString(pubKey)
		return base64string, err
	}
}

func FormatSignature(sigFilePath string) (string, error) {
	sigKey, err := ioutil.ReadFile(sigFilePath)

	if err != nil {
		return "Error opening File: ", err
	}

	if strings.Contains(string(sigKey), "-----BEGIN PGP") {
		// It's an armored file
		buf := bytes.NewReader(sigKey)

		block, err := armor.Decode(buf)

		if err != nil {
			return "Error Decoding: ", err
		}

		if block.Type == "PGP SIGNATURE" {
			reader := packet.NewReader(block.Body)
			pkt, err := reader.Next()
			if err != nil {
				return "Error reading file: ", err
			}

			_, ok := pkt.(*packet.Signature)
			if !ok {
				return ("Invalid Signature Key"), err
			}
		}
		base64string := base64.StdEncoding.EncodeToString(sigKey)
		return base64string, nil

	} else {
		// It's likely a binary file
		pack, err := packet.Read(bytes.NewReader(sigKey))
		if err != nil {
			return "Error reading pub key", err
		}
		_, ok := pack.(*packet.PublicKey)
		if !ok {
			return "Invalid public key.", err
		}
		base64string := base64.StdEncoding.EncodeToString(sigKey)
		return base64string, err
	}
}
