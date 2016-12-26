package main

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/metalnem/runtastic/api"
	"github.com/pkg/errors"
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")

	errMissingCredentials = errors.New("Missing email address or password")
	errNoActivities       = errors.New("There are no activities to backup")

	schemaLocation = strings.Join([]string{
		"http://www.topografix.com/GPX/1/1",
		"http://www.topografix.com/GPX/1/1/gpx.xsd",
		"http://www.garmin.com/xmlschemas/GpxExtensions/v3",
		"http://www.garmin.com/xmlschemas/GpxExtensionsv3.xsd",
		"http://www.garmin.com/xmlschemas/TrackPointExtension/v1",
		"http://www.garmin.com/xmlschemas/TrackPointExtensionv1.xsd",
	}, " ")
)

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

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}

func getCredentials() (string, string, error) {
	email := *email
	password := *password

	if email != "" && password != "" {
		return email, password, nil
	}

	email = os.Getenv("RUNTASTIC_EMAIL")
	password = os.Getenv("RUNTASTIC_PASSWORD")

	if email != "" && password != "" {
		return email, password, nil
	}

	return "", "", errMissingCredentials
}

func getFilename(t time.Time, ext string) string {
	s := t.Local().Format("2006-01-02 15.04.05")
	return fmt.Sprintf("Runtastic %s.%s", s, ext)
}

func archive(filename string, activities []api.Activity) (err error) {
	file, err := os.Create(filename)

	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s", filename)
	}

	defer checkedClose(file, &err)
	zw := zip.NewWriter(file)
	defer checkedClose(zw, &err)

	for _, activity := range activities {
		filename := getFilename(activity.EndTime, "gpx")
		w, err := zw.Create(filename)

		if err != nil {
			return err
		}

		if _, err = fmt.Fprint(w, xml.Header); err != nil {
			return errors.Wrapf(err, "Failed to save activity %s", filename)
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

		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")

		if err = encoder.Encode(data); err != nil {
			return errors.Wrapf(err, "Failed to save activity %s", filename)
		}
	}

	return nil
}

func main() {
	flag.Parse()

	email, password, err := getCredentials()

	if err != nil {
		glog.Exit(err)
	}

	user, err := api.Login(context.Background(), email, password)

	if err != nil {
		glog.Exit(err)
	}

	activities, err := api.GetActivities(context.Background(), user)

	if err != nil {
		glog.Exit(err)
	}

	if len(activities) == 0 {
		glog.Exit(errNoActivities)
	}

	filename := getFilename(time.Now(), "zip")

	if err = archive(filename, activities); err != nil {
		glog.Exit(err)
	}

	glog.Flush()
}
