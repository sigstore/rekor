package cmd

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
)

func addFileToRequest(request *http.Request, path string) error {

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	defer writer.Close()
	part, err := writer.CreateFormFile("fileupload", path)
	if err != nil {
		return err
	}

	if _, err := io.Copy(part, f); err != nil {
		return err
	}

	request.Body = ioutil.NopCloser(body)
	request.Header.Add("Content-Type", writer.FormDataContentType())
	return nil
}
