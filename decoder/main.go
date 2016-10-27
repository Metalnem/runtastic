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

func read(r io.Reader) (trackPoint, error) {
	var point trackPoint
	var timestamp int64

	if err := binary.Read(r, binary.BigEndian, &timestamp); err != nil {
		return trackPoint{}, nil
	}

	point.Time = time.Unix(timestamp/1000, timestamp%1000*1000)

	if err := binary.Read(r, binary.BigEndian, &point.Longitude); err != nil {
		return trackPoint{}, err
	}

	if err := binary.Read(r, binary.BigEndian, &point.Latitude); err != nil {
		return trackPoint{}, err
	}

	if err := binary.Read(r, binary.BigEndian, &point.Elevation); err != nil {
		return trackPoint{}, err
	}

	rest := make([]byte, 18)

	if err := binary.Read(r, binary.BigEndian, rest); err != nil {
		return trackPoint{}, err
	}

	return point, nil
}

func main() {
	raw, err := ioutil.ReadFile("activity.dat")

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

	fmt.Println(size)

	for i := 0; i < int(size); i++ {
		point, err := read(buf)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%+v\n", point)
	}
}
