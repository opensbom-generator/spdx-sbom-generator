// SPDX-License-Identifier: Apache-2.0

package cargo

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

func readCheckSum(content string) string {
	if content == "" {
		return ""
	}
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func removeURLProtocol(str string) string {
	value := strings.ReplaceAll(str, "https://", "")
	value = strings.ReplaceAll(value, "http://", "")
	return value
}

func removeRegisrySuffix(value string) string {
	str := strings.ReplaceAll(value, "registry+", "")
	return str
}
