// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"strings"
)

func removeURLProtocol(str string) string {
	value := strings.ReplaceAll(str, "https://", "")
	value = strings.ReplaceAll(value, "http://", "")
	return value
}
