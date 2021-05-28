package reader

import (
	"encoding/json"
	"io/ioutil"
	"strings"
)

// Reader ...
type Reader struct {
	fileName string
}

// New ...
func New(filename string) *Reader {
	return &Reader{fileName: filename}
}


// GetCopyrightText ...
func (s *Reader) GetCopyrightText() string {
	fByte, err := s.readFile()
	if err != nil {
		return ""
	}

	ind := strings.Index(string(fByte), "Copyright (c)")
	copyWrite := strings.Split(string(fByte)[ind:], `\n`)
	return copyWrite[0]
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
