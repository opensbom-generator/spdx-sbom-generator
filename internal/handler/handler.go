<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
package handler

import ()

// Handler ...
type Handler interface {
	Run() error
	Complete() error
}
