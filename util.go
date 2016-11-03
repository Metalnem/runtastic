package main

import (
	"encoding/binary"
	"io"
)

type reader struct {
	io.Reader
	err error
}

func (r *reader) read(data interface{}) {
	if r.err == nil {
		r.err = binary.Read(r.Reader, binary.BigEndian, data)
	}
}

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}
