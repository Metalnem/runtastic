package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

type trackPoint struct {
	XMLName   xml.Name    `xml:"trkpt"`
	Longitude float32     `xml:"lon,attr"`
	Latitude  float32     `xml:"lat,attr"`
	Elevation float32     `xml:"name>ele"`
	Time      rfc3339Time `xml:"name>time"`
}

type gpx struct {
	XMLName xml.Name `xml:"gpx"`
	Track   track
}

type track struct {
	XMLName xml.Name `xml:"trk"`
	Segment segment
}

type segment struct {
	XMLName xml.Name `xml:"trkseg"`
	Points  []trackPoint
}

type rfc3339Time struct {
	time.Time
}

type reader struct {
	io.Reader
	err error
}

// MarshalXML is a custom XML marshaller that formats time using RFC3339 format.
func (t rfc3339Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	e.EncodeElement(t.Format(time.RFC3339), start)
	return nil
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

	t := time.Unix(timestamp/1000, timestamp%1000*1000)
	point.Time = rfc3339Time{t.UTC()}

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

	var points []trackPoint

	for i := 0; i < int(size); i++ {
		var point trackPoint
		point, err = read(buf)

		if err != nil {
			log.Fatal(err)
		}

		points = append(points, point)
	}

	data := gpx{Track: track{Segment: segment{Points: points}}}
	b, err := xml.MarshalIndent(data, "", "  ")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}
