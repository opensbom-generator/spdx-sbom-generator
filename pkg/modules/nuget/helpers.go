// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
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

func buildRootPackageURL(localPath string) string {
	var url string
	localGit, err := git.PlainOpen(localPath)
	if err != nil {
		return url
	}

	remote, err := localGit.Remote("origin")
	if err != nil {
		return url
	}

	config := remote.Config()
	if err := config.Validate(); err != nil {
		return url
	}
	if len(config.URLs) > 0 {
		url = config.URLs[0]
		if strings.HasPrefix(url, "git@") {
			re := strings.NewReplacer("git@", "https://", ":", "/")
			url = re.Replace(url)
		}
		return fmt.Sprintf("git+%s", url)
	}
	return url
}

func buildDownloadURL(url string) string {
	if strings.HasPrefix(url, "git://") {
		re := strings.NewReplacer("git://", "https://")
		url = re.Replace(url)
		return url
	}
	return url
}
