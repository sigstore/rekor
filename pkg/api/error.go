/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package api

import (
	"net/http"
	"reflect"

	"github.com/go-openapi/runtime/middleware"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"github.com/projectrekor/rekor/pkg/log"
)

const (
	trillianCommunicationError     = "Unexpected error communicating with transparency log"
	trillianUnexpectedResult       = "Unexpected result from transparency log"
	failedToGenerateCanonicalEntry = "Error generating canonicalized entry"
	entryAlreadyExists             = "An equivalent entry already exists in the transparency log"
	firstSizeLessThanLastSize      = "firstSize(%v) must be less than lastSize(%v)"
)

func errorMsg(message string, code int) *models.Error {
	errObj := models.Error{
		Status:  int64(code),
		Message: message,
	}
	return &errObj
}

func logAndReturnError(returnObj middleware.Responder, code int, err error, message string, r *http.Request) middleware.Responder {
	log.RequestIDLogger(r).Errorf("returning %T(%v): message '%v', err '%v'", returnObj, code, message, err)
	errorMsg := errorMsg(message, code)
	if m, ok := reflect.TypeOf(returnObj).MethodByName("WithPayload"); ok {
		args := []reflect.Value{reflect.ValueOf(returnObj), reflect.ValueOf(errorMsg)}
		return m.Func.Call(args)[0].Interface().(middleware.Responder)
	}
	return returnObj
}
