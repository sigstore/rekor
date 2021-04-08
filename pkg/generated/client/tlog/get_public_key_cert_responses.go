// Code generated by go-swagger; DO NOT EDIT.

// /*
// Copyright The Rekor Authors.
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
// */
//

package tlog

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// GetPublicKeyCertReader is a Reader for the GetPublicKeyCert structure.
type GetPublicKeyCertReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPublicKeyCertReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPublicKeyCertOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGetPublicKeyCertDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetPublicKeyCertOK creates a GetPublicKeyCertOK with default headers values
func NewGetPublicKeyCertOK() *GetPublicKeyCertOK {
	return &GetPublicKeyCertOK{}
}

/* GetPublicKeyCertOK describes a response with status code 200, with default header values.

The public key cert
*/
type GetPublicKeyCertOK struct {
	Payload string
}

func (o *GetPublicKeyCertOK) Error() string {
	return fmt.Sprintf("[GET /api/v1/log/publicKeyCert][%d] getPublicKeyCertOK  %+v", 200, o.Payload)
}
func (o *GetPublicKeyCertOK) GetPayload() string {
	return o.Payload
}

func (o *GetPublicKeyCertOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPublicKeyCertDefault creates a GetPublicKeyCertDefault with default headers values
func NewGetPublicKeyCertDefault(code int) *GetPublicKeyCertDefault {
	return &GetPublicKeyCertDefault{
		_statusCode: code,
	}
}

/* GetPublicKeyCertDefault describes a response with status code -1, with default header values.

There was an internal error in the server while processing the request
*/
type GetPublicKeyCertDefault struct {
	_statusCode int

	Payload *models.Error
}

// Code gets the status code for the get public key cert default response
func (o *GetPublicKeyCertDefault) Code() int {
	return o._statusCode
}

func (o *GetPublicKeyCertDefault) Error() string {
	return fmt.Sprintf("[GET /api/v1/log/publicKeyCert][%d] getPublicKeyCert default  %+v", o._statusCode, o.Payload)
}
func (o *GetPublicKeyCertDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetPublicKeyCertDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
