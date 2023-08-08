// Copyright 2023 The Sigstore Authors.
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

package identity

type Identity struct {
	// Types include: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey,
	// *x509.Certificate, openpgp.EntityList, *minisign.PublicKey, ssh.PublicKey
	Crypto any
	// Based on type of Crypto. Possible values include: PEM-encoded public key,
	// PEM-encoded certificate, canonicalized PGP public key, encoded Minisign
	// public key, encoded SSH public key
	Raw []byte
}
