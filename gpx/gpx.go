package gpx

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalnem/runtastic/api"
	"github.com/pkg/errors"
)

var schemaLocation = strings.Join([]string{
	"http://www.topografix.com/GPX/1/1",
	"http://www.topografix.com/GPX/1/1/gpx.xsd",
	"http://www.garmin.com/xmlschemas/GpxExtensions/v3",
	"http://www.garmin.com/xmlschemas/GpxExtensionsv3.xsd",
	"http://www.garmin.com/xmlschemas/TrackPointExtension/v1",
	"http://www.garmin.com/xmlschemas/TrackPointExtensionv1.xsd",
}, " ")

// Exporter writes GPX data to an output stream.
type Exporter struct {
	w io.Writer
}

type rfc3339Time struct {
	time.Time
}

type trackPoint struct {
	Longitude  float32     `xml:"lon,attr"`
	Latitude   float32     `xml:"lat,attr"`
	Elevation  float32     `xml:"ele,omitempty"`
	Time       rfc3339Time `xml:"time,omitempty"`
	Extensions *extensions `xml:"extensions,omitempty"`
}

type extensions struct {
	HeartRate uint8 `xml:"gpxtpx:TrackPointExtension>gpxtpx:hr"`
}

type gpx struct {
	XMLName        xml.Name     `xml:"http://www.topografix.com/GPX/1/1 gpx"`
	Version        float32      `xml:"version,attr"`
	Creator        string       `xml:"creator,attr"`
	SchemaInstance string       `xml:"xmlns:xsi,attr"`
	SchemaLocation string       `xml:"xsi:schemaLocation,attr"`
	Extension      string       `xml:"xmlns:gpxtpx,attr"`
	Time           rfc3339Time  `xml:"metadata>time"`
	TrackPoints    []trackPoint `xml:"trk>trkseg>trkpt"`
}

func (t rfc3339Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	e.EncodeElement(t.Format(time.RFC3339), start)
	return nil
}

// NewExporter returns a new exporter that writes to w.
func NewExporter(w io.Writer) *Exporter {
	return &Exporter{w}
}

// Export writes activity in GPX format to the stream.
func (exp *Exporter) Export(activity api.Activity) (err error) {
	if _, err := fmt.Fprint(exp.w, xml.Header); err != nil {
		return errors.Wrapf(err, "Failed to export activity %s", activity.ID)
	}

	var points []trackPoint

	for _, point := range activity.Data {
		tp := trackPoint{
			Longitude: point.Longitude,
			Latitude:  point.Latitude,
			Elevation: point.Elevation,
			Time:      rfc3339Time{point.Time},
		}

		if point.HeartRate > 0 {
			tp.Extensions = &extensions{HeartRate: point.HeartRate}
		}

		points = append(points, tp)
	}

	data := gpx{
		SchemaInstance: "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLocation: schemaLocation,
		Extension:      "http://www.garmin.com/xmlschemas/TrackPointExtension/v1",
		Version:        1.1,
		Creator:        "Runtastic Archiver, https://github.com/Metalnem/runtastic",
		Time:           rfc3339Time{activity.StartTime},
		TrackPoints:    points,
	}

	encoder := xml.NewEncoder(exp.w)
	encoder.Indent("", "  ")

	if err = encoder.Encode(data); err != nil {
		return errors.Wrapf(err, "Failed to export activity %s", activity.ID)
	}

	return nil
}
