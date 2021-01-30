package ssh

import (
	"io"

	"golang.org/x/crypto/ssh"
)

func Verify(message io.Reader, armoredSignature []byte, publicKey []byte) error {
	decodedSignature, err := Decode(armoredSignature)
	if err != nil {
		return err
	}

	desiredPk, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return err
	}

	// Hash the message so we can verify it against the signature.
	h := supportedHashAlgorithms[decodedSignature.hashAlg]()
	if _, err := io.Copy(h, message); err != nil {
		return err
	}
	hm := h.Sum(nil)

	toVerify := MessageWrapper{
		Namespace:     "file",
		HashAlgorithm: decodedSignature.hashAlg,
		Hash:          string(hm),
	}
	signedMessage := ssh.Marshal(toVerify)
	signedMessage = append([]byte(magicHeader), signedMessage...)
	return desiredPk.Verify(signedMessage, decodedSignature.signature)
}
