/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

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
package util

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// FileOrURLReadCloser Note: caller is responsible for closing ReadCloser returned from method!
func FileOrURLReadCloser(ctx context.Context, url string, content []byte, checkGZIP bool) (io.ReadCloser, error) {
	var dataReader io.ReadCloser
	if url != "" {
		//TODO: set timeout here, SSL settings?
		client := &http.Client{}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("error received while fetching artifact: %v", resp.Status)
		}

		if checkGZIP {
			// read first 512 bytes to determine if content is gzip compressed
			bufReader := bufio.NewReaderSize(resp.Body, 512)
			ctBuf, err := bufReader.Peek(512)
			if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
				return nil, err
			}

			if http.DetectContentType(ctBuf) == "application/x-gzip" {
				dataReader, _ = gzip.NewReader(io.MultiReader(bufReader, resp.Body))
			} else {
				dataReader = ioutil.NopCloser(io.MultiReader(bufReader, resp.Body))
			}
		} else {
			dataReader = resp.Body
		}
	} else {
		dataReader = ioutil.NopCloser(bytes.NewReader(content))
	}
	return dataReader, nil
}
