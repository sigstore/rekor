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

func Armor(s *ssh.Signature, p ssh.PublicKey) string {
	sig := WrappedSig{
		Version:       1,
		PublicKey:     string(p.Marshal()),
		Namespace:     namespace,
		HashAlgorithm: hashAlgorithm,
		Signature:     string(ssh.Marshal(s)),
	}
	copy(sig.MagicHeader[:], []byte(magicHeader))

	enc := pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: ssh.Marshal(sig),
	})
	return string(enc)
}

func Decode(s string) (*ssh.Signature, ssh.PublicKey, error) {
	pemBlock, _ := pem.Decode([]byte(s))
	if pemBlock == nil {
		return nil, nil, errors.New("unable to decode pem file")
	}

	if pemBlock.Type != pemType {
		return nil, nil, fmt.Errorf("wrong pem block type: %s. Expected SSH-SIGNATURE", pemBlock.Type)
	}

	// Now we unmarshal it into the Signature block
	sig := WrappedSig{}
	if err := ssh.Unmarshal(pemBlock.Bytes, &sig); err != nil {
		return nil, nil, err
	}

	if sig.Version != 1 {
		return nil, nil, fmt.Errorf("unsupported signature version: %d", sig.Version)
	}
	if string(sig.MagicHeader[:]) != magicHeader {
		return nil, nil, fmt.Errorf("invalid magic header: %s", sig.MagicHeader)
	}
	if sig.Namespace != "file" {
		return nil, nil, fmt.Errorf("invalid signature namespace: %s", sig.Namespace)
	}
	// TODO: Also check the HashAlgorithm type here.

	// Now we can unpack the Signature and PublicKey blocks
	sshSig := ssh.Signature{}
	if err := ssh.Unmarshal([]byte(sig.Signature), &sshSig); err != nil {
		return nil, nil, err
	}
	// TODO: check the format here (should be rsa-sha512)

	pk, err := ssh.ParsePublicKey([]byte(sig.PublicKey))
	if err != nil {
		return nil, nil, err
	}

	return &sshSig, pk, nil
}
