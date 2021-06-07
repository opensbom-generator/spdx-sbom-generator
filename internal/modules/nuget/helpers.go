// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"fmt"
	"net/http"
	"time"
)

func genUrl(packageName string, packageVersion string) string {
	if packageName == "" || packageVersion == "" {
		return ""
	}
	return fmt.Sprintf("pkg:nuget/%s@%s", packageName, packageVersion)
}

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
