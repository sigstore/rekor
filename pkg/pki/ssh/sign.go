package ssh

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/ssh"
)

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L81
type MessageWrapper struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          string
}

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L34
type WrappedSig struct {
	MagicHeader   [6]byte
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

const (
	magicHeader   = "SSHSIG"
	hashAlgorithm = "sha512"
)

func sign(s ssh.AlgorithmSigner, m io.Reader) (*ssh.Signature, error) {

	hf := sha512.New()
	if _, err := io.Copy(hf, m); err != nil {
		return nil, err
	}
	mh := hf.Sum(nil)

	sp := MessageWrapper{
		Namespace:     "file",
		HashAlgorithm: hashAlgorithm,
		Hash:          string(mh),
	}

	dataMessageWrapper := ssh.Marshal(sp)
	dataMessageWrapper = append([]byte(magicHeader), dataMessageWrapper...)

	sig, err := s.SignWithAlgorithm(rand.Reader, dataMessageWrapper, ssh.SigAlgoRSASHA2512)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func Sign(sshPrivateKey string, data io.Reader) ([]byte, error) {
	s, err := ssh.ParsePrivateKey([]byte(sshPrivateKey))
	if err != nil {
		return nil, err
	}

	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, err
	}

	sig, err := sign(as, data)
	if err != nil {
		return nil, err
	}

	armored := Armor(sig, s.PublicKey())
	return armored, nil
}
