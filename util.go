package main

import (
	"encoding/binary"
	"encoding/xml"
	"io"
	"strconv"
	"time"
)

type jsonBool string
type jsonTime string
type timestamp int64

type reader struct {
	io.Reader
	err error
}

type rfc3339Time struct {
	time.Time
}

func (b jsonBool) Bool() (bool, error) {
	if b == "" {
		return false, nil
	}

	return strconv.ParseBool(string(b))
}

func (t jsonTime) Time() (time.Time, error) {
	tx, err := strconv.ParseInt(string(t), 10, 64)

	if err != nil {
		return time.Time{}, err
	}

	return timestamp(tx).toUtcTime(), nil
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

// MarshalXML is a custom XML marshaller that formats time using RFC3339 format.
func (t rfc3339Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	e.EncodeElement(t.Format(time.RFC3339), start)
	return nil
}

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}
