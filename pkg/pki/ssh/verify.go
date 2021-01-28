package ssh

import (
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/ssh"
)

func Verify(message io.Reader, armoredSignature string, publicKey []byte) error {
	decodedSignature, _, err := Decode(armoredSignature)
	if err != nil {
		return err
	}

	desiredPk, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return err
	}

	// Hash the message so we can verify it against the signature.
	h := sha512.New()
	if _, err := io.Copy(h, message); err != nil {
		return err
	}
	hm := h.Sum(nil)

	toVerify := MessageWrapper{
		Namespace:     "file",
		HashAlgorithm: "sha512",
		Hash:          string(hm),
	}
	signedMessage := ssh.Marshal(toVerify)
	signedMessage = append([]byte(magicHeader), signedMessage...)
	return desiredPk.Verify(signedMessage, decodedSignature)
}
