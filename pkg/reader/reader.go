// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"encoding/json"
	"io/ioutil"
)

// Reader ...
type Reader struct {
	fileName string
}

// New ...
func New(filename string) *Reader {
	return &Reader{fileName: filename}
}


// StringFromFile ...
func (s *Reader) StringFromFile() string {
	fByte, err := s.readFile()
	if err != nil {
		return ""
	}

	return string(fByte)

}

// ReadJson ...
func (s *Reader) ReadJson() (map[string]interface{},error) {
	fByte, err := s.readFile()
	if err != nil {
		return nil, err
	}
	var jResult map[string]interface{}
	err = json.Unmarshal(fByte, &jResult)
	if err != nil {
		return nil, err
	}

	return jResult, nil
}


func (s *Reader) readFile() ([]byte, error) {
	return ioutil.ReadFile(s.fileName)
}
