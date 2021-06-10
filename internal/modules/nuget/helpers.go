// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"net/http"
	"strings"
	"time"
)

func getHttpResponseWithHeaders(url string, headers map[string]string) (*http.Response, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 30,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for headerKey, headerValue := range headers {
		req.Header.Add(headerKey, headerValue)
	}

	response, err := netClient.Do(req)
	if err != nil {
		return nil, err
	}

	return response, err
}

func removeURLProtocol(str string) string {
	value := strings.ReplaceAll(str, "https://", "")
	value = strings.ReplaceAll(value, "http://", "")
	return value
}
