package handler

import ()

// Handler ...
type Handler interface {
	Run() error
	Complete() error
}
