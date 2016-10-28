package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

type trackPoint struct {
	Longitude float32
	Latitude  float32
	Elevation float32
	Time      time.Time
}

type reader struct {
	io.Reader
	err error
}

func (r *reader) read(data interface{}) {
	if r.err == nil {
		r.err = binary.Read(r.Reader, binary.BigEndian, data)
	}
}

func read(input io.Reader) (trackPoint, error) {
	var point trackPoint
	var timestamp int64

	unknown := make([]byte, 18)
	r := reader{input, nil}

	r.read(&timestamp)
	r.read(&point.Longitude)
	r.read(&point.Latitude)
	r.read(&point.Elevation)
	r.read(unknown)

	if r.err != nil {
		return trackPoint{}, r.err
	}

	point.Time = time.Unix(timestamp/1000, timestamp%1000*1000)

	return point, nil
}

func main() {
	raw, err := ioutil.ReadFile("large-activity.dat")

	if err != nil {
		log.Fatal(err)
	}

	encoded := strings.Split(string(raw), "\\n")
	var decoded []byte

	for _, line := range encoded {
		var b []byte
		b, err = base64.StdEncoding.DecodeString(line)

		if err != nil {
			log.Fatal(err)
		}

		decoded = append(decoded, b...)
	}

	buf := bytes.NewBuffer(decoded)
	var size int32

	if err = binary.Read(buf, binary.BigEndian, &size); err != nil {
		log.Fatal(err)
	}

	for i := 0; i < int(size); i++ {
		point, err := read(buf)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%+v\n", point)
	}
}
