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

package entries

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// GetLogEntryByIndexReader is a Reader for the GetLogEntryByIndex structure.
type GetLogEntryByIndexReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLogEntryByIndexReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLogEntryByIndexOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewGetLogEntryByIndexNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewGetLogEntryByIndexDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetLogEntryByIndexOK creates a GetLogEntryByIndexOK with default headers values
func NewGetLogEntryByIndexOK() *GetLogEntryByIndexOK {
	return &GetLogEntryByIndexOK{}
}

/* GetLogEntryByIndexOK describes a response with status code 200, with default header values.

the entry in the transparency log requested
*/
type GetLogEntryByIndexOK struct {
	Payload models.LogEntry
}

func (o *GetLogEntryByIndexOK) Error() string {
	return fmt.Sprintf("[GET /api/v1/log/entries][%d] getLogEntryByIndexOK  %+v", 200, o.Payload)
}
func (o *GetLogEntryByIndexOK) GetPayload() models.LogEntry {
	return o.Payload
}

func (o *GetLogEntryByIndexOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLogEntryByIndexNotFound creates a GetLogEntryByIndexNotFound with default headers values
func NewGetLogEntryByIndexNotFound() *GetLogEntryByIndexNotFound {
	return &GetLogEntryByIndexNotFound{}
}

/* GetLogEntryByIndexNotFound describes a response with status code 404, with default header values.

The content requested could not be found
*/
type GetLogEntryByIndexNotFound struct {
}

func (o *GetLogEntryByIndexNotFound) Error() string {
	return fmt.Sprintf("[GET /api/v1/log/entries][%d] getLogEntryByIndexNotFound ", 404)
}

func (o *GetLogEntryByIndexNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetLogEntryByIndexDefault creates a GetLogEntryByIndexDefault with default headers values
func NewGetLogEntryByIndexDefault(code int) *GetLogEntryByIndexDefault {
	return &GetLogEntryByIndexDefault{
		_statusCode: code,
	}
}

/* GetLogEntryByIndexDefault describes a response with status code -1, with default header values.

There was an internal error in the server while processing the request
*/
type GetLogEntryByIndexDefault struct {
	_statusCode int

	Payload *models.Error
}

// Code gets the status code for the get log entry by index default response
func (o *GetLogEntryByIndexDefault) Code() int {
	return o._statusCode
}

func (o *GetLogEntryByIndexDefault) Error() string {
	return fmt.Sprintf("[GET /api/v1/log/entries][%d] getLogEntryByIndex default  %+v", o._statusCode, o.Payload)
}
func (o *GetLogEntryByIndexDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLogEntryByIndexDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
