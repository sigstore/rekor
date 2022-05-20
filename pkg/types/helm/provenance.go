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

package helm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ghodss/yaml"

	"golang.org/x/crypto/openpgp/clearsign"
)

type Provenance struct {
	ChartMetadata map[string]string
	SumCollection *SumCollection
	Block         *clearsign.Block
}

type SumCollection struct {
	Files  map[string]string `json:"files"`
	Images map[string]string `json:"images,omitempty"`
}

func (p *Provenance) Unmarshal(reader io.Reader) error {
	buf := &bytes.Buffer{}
	read, err := buf.ReadFrom(reader)
	if err != nil {
		return errors.New("Failed to read from buffer")
	} else if read == 0 {
		return errors.New("Provenance file contains no content")
	}

	block, _ := clearsign.Decode(buf.Bytes())
	if block == nil {
		return errors.New("Unable to decode provenance file")
	}

	if block.ArmoredSignature == nil {
		return errors.New("Unable to locate armored signature in provenance file")
	}

	if err = p.parseMessageBlock(block.Plaintext); err != nil {
		return fmt.Errorf("Error occurred parsing message block: %w", err)
	}

	p.Block = block
	return nil
}

func (p *Provenance) parseMessageBlock(data []byte) error {

	parts := bytes.Split(data, []byte("\n...\n"))
	if len(parts) < 2 {
		return errors.New("message block must have at least two parts")
	}

	sc := &SumCollection{}

	if err := yaml.Unmarshal(parts[1], sc); err != nil {
		return fmt.Errorf("Error occurred parsing SumCollection: %w", err)
	}

	p.SumCollection = sc

	return nil
}

func (p *Provenance) GetChartAlgorithmHash() (string, string, error) {

	if p.SumCollection == nil || p.SumCollection.Files == nil {
		return "", "", errors.New("Unable to locate chart hash")
	}

	for _, value := range p.SumCollection.Files {
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return "", "", errors.New("Invalid hash found in Provenance file")
		}

		return parts[0], parts[1], nil
	}

	// Return error if no keys found
	return "", "", errors.New("No checksums found")

}
