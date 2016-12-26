package api

import (
	"encoding/binary"
	"io"
	"strconv"
	"time"
)

type jsonBool string
type jsonTime time.Time
type timestamp int64

type reader struct {
	io.Reader
	err error
}

func (b jsonBool) Bool() (bool, error) {
	if b == "" {
		return false, nil
	}

	return strconv.ParseBool(string(b))
}

func (t *jsonTime) UnmarshalJSON(b []byte) error {
	s := string(b)

	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return errInvalidTime
	}

	time, err := strconv.ParseInt(s[1:len(s)-1], 10, 64)

	if err != nil {
		return errInvalidTime
	}

	*t = jsonTime(timestamp(time).toUtcTime())
	return nil
}

func (t timestamp) toLocalTime() time.Time {
	return time.Unix(int64(t)/1000, int64(t)%1000*1000)
}

func (t timestamp) toUtcTime() time.Time {
	return t.toLocalTime().UTC()
}

func (r *reader) read(data interface{}) {
	if r.err == nil {
		r.err = binary.Read(r.Reader, binary.BigEndian, data)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}
