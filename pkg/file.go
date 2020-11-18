package pkg

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
)

func AddFileToRequest(request *http.Request, r io.Reader) error {

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	defer writer.Close()
	part, err := writer.CreateFormFile("fileupload", "linkfile")
	if err != nil {
		return err
	}

	if _, err := io.Copy(part, r); err != nil {
		return err
	}

	request.Body = ioutil.NopCloser(body)
	request.Header.Add("Content-Type", writer.FormDataContentType())
	return nil
}
