// SPDX-License-Identifier: Apache-2.0

package worker

func IsRequirementMeet(root bool, data string) bool {
	_modules := LoadModules(data)
	if root && len(_modules) == 1 {
		return true
	} else if !root && len(_modules) > 3 {
		return true
	}
	return false
}
