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

package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/sharding"

	"github.com/spf13/pflag"

	validator "github.com/asaskevich/govalidator"
)

type FlagType string

const (
	uuidFlag           FlagType = "uuid"
	shaFlag            FlagType = "sha"
	emailFlag          FlagType = "email"
	operatorFlag       FlagType = "operator"
	logIndexFlag       FlagType = "logIndex"
	pkiFormatFlag      FlagType = "pkiFormat"
	typeFlag           FlagType = "type"
	fileFlag           FlagType = "file"
	urlFlag            FlagType = "url"
	fileOrURLFlag      FlagType = "fileOrURL"
	multiFileOrURLFlag FlagType = "multiFileOrURL"
	oidFlag            FlagType = "oid"
	formatFlag         FlagType = "format"
	timeoutFlag        FlagType = "timeout"
	base64Flag         FlagType = "base64"
	uintFlag           FlagType = "uint"
)

type newPFlagValueFunc func() pflag.Value

var pflagValueFuncMap map[FlagType]newPFlagValueFunc

// TODO: unit tests for all of this
func initializePFlagMap() {
	pflagValueFuncMap = map[FlagType]newPFlagValueFunc{
		uuidFlag: func() pflag.Value {
			// this validates a UUID with or without a prepended TreeID;
			// the UUID corresponds to the merkle leaf hash of entries,
			// which is represented by a 64 character hexadecimal string
			return valueFactory(uuidFlag, validateID, "")
		},
		shaFlag: func() pflag.Value {
			// this validates a valid sha256 checksum which is optionally prefixed with 'sha256:'
			return valueFactory(shaFlag, validateSHAValue, "")
		},
		operatorFlag: func() pflag.Value {
			// this validates a valid operator name
			operatorFlagValidator := func(val string) error {
				o := struct {
					Value string `valid:in(and|or)`
				}{val}
				_, err := validator.ValidateStruct(o)
				return err
			}
			return valueFactory(operatorFlag, operatorFlagValidator, "")
		},
		emailFlag: func() pflag.Value {
			// this validates an email address
			emailValidator := func(val string) error {
				if !validator.IsEmail(val) {
					return fmt.Errorf("'%v' is not a valid email address", val)
				}
				return nil
			}
			return valueFactory(emailFlag, emailValidator, "")
		},
		logIndexFlag: func() pflag.Value {
			// this checks for a valid integer >= 0
			return valueFactory(logIndexFlag, validateUint, "")
		},
		pkiFormatFlag: func() pflag.Value {
			// this ensures a PKI implementation exists for the requested format
			pkiFormatValidator := func(val string) error {
				if !validator.IsIn(val, pki.SupportedFormats()...) {
					return fmt.Errorf("'%v' is not a valid pki format", val)
				}
				return nil
			}
			return valueFactory(pkiFormatFlag, pkiFormatValidator, "pgp")
		},
		typeFlag: func() pflag.Value {
			// this ensures the type of the log entry matches a type supported in the CLI
			return valueFactory(typeFlag, validateTypeFlag, "rekord")
		},
		fileFlag: func() pflag.Value {
			// this validates that the file exists and can be opened by the current uid
			return valueFactory(fileFlag, validateFile, "")
		},
		urlFlag: func() pflag.Value {
			// this validates that the string is a valid http/https URL
			httpHttpsValidator := func(val string) error {
				if !validator.IsURL(val) {
					return fmt.Errorf("'%v' is not a valid url", val)
				}
				if !(strings.HasPrefix(val, "http") || strings.HasPrefix(val, "https")) {
					return errors.New("URL must be for http or https scheme")
				}
				return nil
			}
			return valueFactory(urlFlag, httpHttpsValidator, "")
		},
		fileOrURLFlag: func() pflag.Value {
			// applies logic of fileFlag OR urlFlag validators from above
			return valueFactory(fileOrURLFlag, validateFileOrURL, "")
		},
		multiFileOrURLFlag: func() pflag.Value {
			// applies logic of fileFlag OR urlFlag validators from above for multi file and URL
			return multiValueFactory(multiFileOrURLFlag, validateFileOrURL, []string{})
		},
		oidFlag: func() pflag.Value {
			// this validates for an OID, which is a sequence of positive integers separated by periods
			return valueFactory(oidFlag, validateOID, "")
		},
		formatFlag: func() pflag.Value {
			// this validates the output format requested
			formatValidator := func(val string) error {
				if !validator.IsIn(val, "json", "default", "tle") {
					return fmt.Errorf("'%v' is not a valid output format", val)
				}
				return nil
			}
			return valueFactory(formatFlag, formatValidator, "")
		},
		timeoutFlag: func() pflag.Value {
			// this validates the timeout is >= 0
			return valueFactory(formatFlag, validateTimeout, "")
		},
		base64Flag: func() pflag.Value {
			// This validates the string is in base64 format
			return valueFactory(base64Flag, validateBase64, "")
		},
		uintFlag: func() pflag.Value {
			// This validates the string is in base64 format
			return valueFactory(uintFlag, validateUint, "")
		},
	}
}

// NewFlagValue creates a new pflag.Value for the specified type with the specified default value.
// If a default value is not desired, pass "" for defaultVal.
func NewFlagValue(flagType FlagType, defaultVal string) pflag.Value {
	valFunc := pflagValueFuncMap[flagType]
	val := valFunc()
	if defaultVal != "" {
		if err := val.Set(defaultVal); err != nil {
			log.Fatal(fmt.Errorf("initializing flag: %w", err))
		}
	}
	return val
}

type validationFunc func(string) error

func valueFactory(flagType FlagType, v validationFunc, defaultVal string) pflag.Value {
	return &baseValue{
		flagType:       flagType,
		validationFunc: v,
		value:          defaultVal,
	}
}

func multiValueFactory(flagType FlagType, v validationFunc, defaultVal []string) pflag.Value {
	return &multiBaseValue{
		flagType:       flagType,
		validationFunc: v,
		value:          defaultVal,
	}
}

// multiBaseValue implements pflag.Value
type multiBaseValue struct {
	flagType       FlagType
	value          []string
	validationFunc validationFunc
}

func (b *multiBaseValue) String() string {
	return strings.Join(b.value, ",")
}

// Type returns the type of this Value
func (b multiBaseValue) Type() string {
	return string(b.flagType)
}

func (b *multiBaseValue) Set(value string) error {
	if err := b.validationFunc(value); err != nil {
		return err
	}
	b.value = append(b.value, value)
	return nil
}

// baseValue implements pflag.Value
type baseValue struct {
	flagType       FlagType
	value          string
	validationFunc validationFunc
}

// Type returns the type of this Value
func (b baseValue) Type() string {
	return string(b.flagType)
}

// String returns the string representation of this Value
func (b baseValue) String() string {
	return b.value
}

// Set validates the provided string against the appropriate validation rule
// for b.flagType; if the string validates, it is stored in the Value and nil is returned.
// Otherwise the validation error is returned but the state of the Value is not changed.
func (b *baseValue) Set(s string) error {
	if err := b.validationFunc(s); err != nil {
		return err
	}
	b.value = s
	return nil
}

// isURL returns true if the supplied value is a valid URL and false otherwise
func isURL(v string) bool {
	valGen := pflagValueFuncMap[urlFlag]
	return valGen().Set(v) == nil
}

// validateSHAValue ensures that the supplied string matches the following formats:
// [sha512:]<128 hexadecimal characters>
// [sha256:]<64 hexadecimal characters>
// [sha1:]<40 hexadecimal characters>
// where [sha256:] and [sha1:] are optional
func validateSHAValue(v string) error {
	err := validateSHA1Value(v)
	if err == nil {
		return nil
	}

	err = validateSHA256Value(v)
	if err == nil {
		return nil
	}

	err = validateSHA512Value(v)
	if err == nil {
		return nil
	}

	return fmt.Errorf("error parsing %v flag: %w", shaFlag, err)
}

// validateFileOrURL ensures the provided string is either a valid file path that can be opened or a valid URL
func validateFileOrURL(v string) error {
	valGen := pflagValueFuncMap[fileFlag]
	if valGen().Set(v) == nil {
		return nil
	}
	valGen = pflagValueFuncMap[urlFlag]
	return valGen().Set(v)
}

// validateID ensures the ID is either an EntryID (TreeID + UUID) or a UUID
func validateID(v string) error {
	if len(v) != sharding.EntryIDHexStringLen && len(v) != sharding.UUIDHexStringLen {
		return fmt.Errorf("ID len error, expected %v (EntryID) or %v (UUID) but got len %v for ID %v", sharding.EntryIDHexStringLen, sharding.UUIDHexStringLen, len(v), v)
	}

	if !validator.IsHexadecimal(v) {
		return fmt.Errorf("invalid uuid: %v", v)
	}

	return nil
}

// validateOID ensures that the supplied string is a valid ASN.1 object identifier
func validateOID(v string) error {
	values := strings.Split(v, ".")
	for _, value := range values {
		if !validator.IsNumeric(value) {
			return fmt.Errorf("field '%v' is not a valid number", value)
		}
	}

	return nil
}

// validateTimeout ensures that the supplied string is a valid time.Duration value >= 0
func validateTimeout(v string) error {
	duration, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	if duration < 0 {
		return errors.New("timeout must be a positive value")
	}
	return nil
}

// validateBase64 ensures that the supplied string is valid base64 encoded data
func validateBase64(v string) error {
	_, err := base64.StdEncoding.DecodeString(v)

	return err
}

// validateTypeFlag ensures that the string is in the format type(\.version)? and
// that one of the types requested is implemented
func validateTypeFlag(v string) error {
	_, _, err := ParseTypeFlag(v)
	return err
}

// validateUint ensures that the supplied string is a valid unsigned integer >= 0
func validateUint(v string) error {
	i, err := strconv.Atoi(v)
	if err != nil {
		return err
	}
	if i < 0 {
		return fmt.Errorf("invalid unsigned int: %v", v)
	}
	return nil
}

// validateFile ensures that the supplied string is a valid path to a file that exists
func validateFile(v string) error {
	fileInfo, err := os.Stat(filepath.Clean(v))
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		return errors.New("path to a directory was provided")
	}
	return nil
}

