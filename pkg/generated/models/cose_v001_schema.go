// Code generated by go-swagger; DO NOT EDIT.

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
//

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// CoseV001Schema cose v0.0.1 Schema
//
// Schema for cose object
//
// swagger:model coseV001Schema
type CoseV001Schema struct {

	// data
	// Required: true
	Data *CoseV001SchemaData `json:"data"`

	// The COSE Sign1 Message
	// Required: true
	// Format: byte
	Message *strfmt.Base64 `json:"message"`

	// The public key that can verify the signature
	// Required: true
	// Format: byte
	PublicKey *strfmt.Base64 `json:"publicKey"`
}

// Validate validates this cose v001 schema
func (m *CoseV001Schema) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMessage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicKey(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001Schema) validateData(formats strfmt.Registry) error {

	if err := validate.Required("data", "body", m.Data); err != nil {
		return err
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

func (m *CoseV001Schema) validateMessage(formats strfmt.Registry) error {

	if err := validate.Required("message", "body", m.Message); err != nil {
		return err
	}

	return nil
}

func (m *CoseV001Schema) validatePublicKey(formats strfmt.Registry) error {

	if err := validate.Required("publicKey", "body", m.PublicKey); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this cose v001 schema based on the context it is used
func (m *CoseV001Schema) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001Schema) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if m.Data != nil {
		if err := m.Data.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001Schema) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001Schema) UnmarshalBinary(b []byte) error {
	var res CoseV001Schema
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// CoseV001SchemaData Information about the content associated with the entry
//
// swagger:model CoseV001SchemaData
type CoseV001SchemaData struct {

	// Specifies the content inline within the document
	// Required: true
	// Format: byte
	Content *strfmt.Base64 `json:"content"`

	// hash
	Hash *CoseV001SchemaDataHash `json:"hash,omitempty"`
}

// Validate validates this cose v001 schema data
func (m *CoseV001SchemaData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHash(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001SchemaData) validateContent(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"content", "body", m.Content); err != nil {
		return err
	}

	return nil
}

func (m *CoseV001SchemaData) validateHash(formats strfmt.Registry) error {
	if swag.IsZero(m.Hash) { // not required
		return nil
	}

	if m.Hash != nil {
		if err := m.Hash.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data" + "." + "hash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data" + "." + "hash")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this cose v001 schema data based on the context it is used
func (m *CoseV001SchemaData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateHash(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CoseV001SchemaData) contextValidateHash(ctx context.Context, formats strfmt.Registry) error {

	if m.Hash != nil {
		if err := m.Hash.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data" + "." + "hash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data" + "." + "hash")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001SchemaData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001SchemaData) UnmarshalBinary(b []byte) error {
	var res CoseV001SchemaData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// CoseV001SchemaDataHash Specifies the hash algorithm and value for the content
//
// swagger:model CoseV001SchemaDataHash
type CoseV001SchemaDataHash struct {

	// The hashing function used to compute the hash value
	// Required: true
	// Enum: [sha256]
	Algorithm *string `json:"algorithm"`

	// The hash value for the content
	// Required: true
	Value *string `json:"value"`
}

// Validate validates this cose v001 schema data hash
func (m *CoseV001SchemaDataHash) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAlgorithm(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var coseV001SchemaDataHashTypeAlgorithmPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sha256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		coseV001SchemaDataHashTypeAlgorithmPropEnum = append(coseV001SchemaDataHashTypeAlgorithmPropEnum, v)
	}
}

const (

	// CoseV001SchemaDataHashAlgorithmSha256 captures enum value "sha256"
	CoseV001SchemaDataHashAlgorithmSha256 string = "sha256"
)

// prop value enum
func (m *CoseV001SchemaDataHash) validateAlgorithmEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, coseV001SchemaDataHashTypeAlgorithmPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *CoseV001SchemaDataHash) validateAlgorithm(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"hash"+"."+"algorithm", "body", m.Algorithm); err != nil {
		return err
	}

	// value enum
	if err := m.validateAlgorithmEnum("data"+"."+"hash"+"."+"algorithm", "body", *m.Algorithm); err != nil {
		return err
	}

	return nil
}

func (m *CoseV001SchemaDataHash) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("data"+"."+"hash"+"."+"value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this cose v001 schema data hash based on context it is used
func (m *CoseV001SchemaDataHash) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CoseV001SchemaDataHash) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CoseV001SchemaDataHash) UnmarshalBinary(b []byte) error {
	var res CoseV001SchemaDataHash
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
