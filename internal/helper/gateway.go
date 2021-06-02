// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	Http *http.Client
}

// NewClient
// todo: complete proper client settings
func NewClient() *Client {
	return &Client{
		Http: &http.Client{
			Timeout: time.Second * 5,
		},
	}
}

// IsValidURL ...
func (c *Client) ParseURL(uri string) *url.URL {
	u, err := url.Parse(uri)
	if err == nil && u.Scheme == "" {
		u.Scheme = "http"
	}

	return u
}

// CheckURL ...
func (c *Client) CheckURL(url string) bool {
	r, err := c.Http.Get(url)
	if err != nil {
		return false
	}
	defer r.Body.Close()

	return r.StatusCode == http.StatusOK
}
