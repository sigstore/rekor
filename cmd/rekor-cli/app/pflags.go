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
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/util"

	"github.com/spf13/pflag"

	validator "github.com/go-playground/validator/v10"
)

type FlagType string

const (
	uuidFlag      FlagType = "uuid"
	shaFlag       FlagType = "sha"
	emailFlag     FlagType = "email"
	logIndexFlag  FlagType = "logIndex"
	pkiFormatFlag FlagType = "pkiFormat"
	typeFlag      FlagType = "type"
	fileFlag      FlagType = "file"
	urlFlag       FlagType = "url"
	fileOrURLFlag FlagType = "fileOrURL"
	oidFlag       FlagType = "oid"
	formatFlag    FlagType = "format"
	timeoutFlag   FlagType = "timeout"
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
		emailFlag: func() pflag.Value {
			// this validates an email address
			return valueFactory(emailFlag, validateString("required,email"), "")
		},
		logIndexFlag: func() pflag.Value {
			// this checks for a valid integer >= 0
			return valueFactory(logIndexFlag, validateLogIndex, "")
		},
		pkiFormatFlag: func() pflag.Value {
			// this ensures a PKI implementation exists for the requested format
			return valueFactory(pkiFormatFlag, validateString(fmt.Sprintf("required,oneof=%v", strings.Join(pki.SupportedFormats(), " "))), "pgp")
		},
		typeFlag: func() pflag.Value {
			// this ensures the type of the log entry matches a type supported in the CLI
			return valueFactory(typeFlag, validateTypeFlag, "rekord")
		},
		fileFlag: func() pflag.Value {
			// this validates that the file exists and can be opened by the current uid
			return valueFactory(fileFlag, validateString("required,file"), "")
		},
		urlFlag: func() pflag.Value {
			// this validates that the string is a valid http/https URL
			return valueFactory(urlFlag, validateString("required,url,startswith=http|startswith=https"), "")
		},
		fileOrURLFlag: func() pflag.Value {
			// applies logic of fileFlag OR urlFlag validators from above
			return valueFactory(fileOrURLFlag, validateFileOrURL, "")
		},
		oidFlag: func() pflag.Value {
			// this validates for an OID, which is a sequence of positive integers separated by periods
			return valueFactory(oidFlag, validateOID, "")
		},
		formatFlag: func() pflag.Value {
			// this validates the output format requested
			return valueFactory(formatFlag, validateString("required,oneof=json default"), "")
		},
		timeoutFlag: func() pflag.Value {
			// this validates the timeout is >= 0
			return valueFactory(formatFlag, validateTimeout, "")
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
// [sha256:]<64 hexadecimal characters>
// [sha1:]<40 hexadecimal characters>
// where [sha256:] and [sha1:] are optional
func validateSHAValue(v string) error {
	err := util.ValidateSHA1Value(v)
	if err == nil {
		return nil
	}

	if err := util.ValidateSHA256Value(v); err != nil {
		return fmt.Errorf("error parsing %v flag: %w", shaFlag, err)
	}

	return nil
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

	if err := validateString("required,hexadecimal")(v); err != nil {
		return fmt.Errorf("invalid uuid: %v", v)
	}

	return nil
}

// validateLogIndex ensures that the supplied string is a valid log index (integer >= 0)
func validateLogIndex(v string) error {
	i, err := strconv.Atoi(v)
	if err != nil {
		return err
	}
	l := struct {
		Index int `validate:"gte=0"`
	}{i}

	return useValidator(logIndexFlag, l)
}

// validateOID ensures that the supplied string is a valid ASN.1 object identifier
func validateOID(v string) error {
	o := struct {
		Oid []string `validate:"dive,numeric"`
	}{strings.Split(v, ".")}

	return useValidator(oidFlag, o)
}

// validateTimeout ensures that the supplied string is a valid time.Duration value >= 0
func validateTimeout(v string) error {
	duration, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	d := struct {
		Duration time.Duration `validate:"min=0"`
	}{duration}
	return useValidator(timeoutFlag, d)
}

// validateTypeFlag ensures that the string is in the format type(\.version)? and
// that one of the types requested is implemented
func validateTypeFlag(v string) error {
	_, _, err := ParseTypeFlag(v)
	return err
}

// validateString returns a function that validates an input string against the specified tag,
// as defined in the format supported by go-playground/validator
func validateString(tag string) validationFunc {
	return func(v string) error {
		validator := validator.New()
		return validator.Var(v, tag)
	}
}

// useValidator performs struct level validation on s as defined in the struct's tags using
// the go-playground/validator library
func useValidator(flagType FlagType, s interface{}) error {
	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return fmt.Errorf("error parsing %v flag: %w", flagType, err)
	}

	return nil
}
