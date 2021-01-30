package ssh

import (
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	namespace = "file"
	pemType   = "SSH SIGNATURE"
)

func Armor(s *ssh.Signature, p ssh.PublicKey) []byte {
	sig := WrappedSig{
		Version:       1,
		PublicKey:     string(p.Marshal()),
		Namespace:     namespace,
		HashAlgorithm: defaultHashAlgorithm,
		Signature:     string(ssh.Marshal(s)),
	}
	copy(sig.MagicHeader[:], []byte(magicHeader))

	enc := pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: ssh.Marshal(sig),
	})
	return enc
}

func Decode(b []byte) (*Signature, error) {
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
		return nil, errors.New("unable to decode pem file")
	}

	if pemBlock.Type != pemType {
		return nil, fmt.Errorf("wrong pem block type: %s. Expected SSH-SIGNATURE", pemBlock.Type)
	}

	// Now we unmarshal it into the Signature block
	sig := WrappedSig{}
	if err := ssh.Unmarshal(pemBlock.Bytes, &sig); err != nil {
		return nil, err
	}

	if sig.Version != 1 {
		return nil, fmt.Errorf("unsupported signature version: %d", sig.Version)
	}
	if string(sig.MagicHeader[:]) != magicHeader {
		return nil, fmt.Errorf("invalid magic header: %s", sig.MagicHeader)
	}
	if sig.Namespace != "file" {
		return nil, fmt.Errorf("invalid signature namespace: %s", sig.Namespace)
	}
	if _, ok := supportedHashAlgorithms[sig.HashAlgorithm]; !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", sig.HashAlgorithm)
	}

	// Now we can unpack the Signature and PublicKey blocks
	sshSig := ssh.Signature{}
	if err := ssh.Unmarshal([]byte(sig.Signature), &sshSig); err != nil {
		return nil, err
	}
	// TODO: check the format here (should be rsa-sha512)

	pk, err := ssh.ParsePublicKey([]byte(sig.PublicKey))
	if err != nil {
		return nil, err
	}

	return &Signature{
		signature: &sshSig,
		pk:        pk,
		hashAlg:   sig.HashAlgorithm,
	}, nil
}
