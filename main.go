package main

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/metalnem/runtastic/api"
	"github.com/pkg/errors"
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")

	errMissingCredentials = errors.New("Missing email address or password")
	errNoActivities       = errors.New("There are no activities to backup")

	// Info is used for logging information.
	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

	// Error is used for logging errors.
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
)

type rfc3339Time struct {
	time.Time
}

type trackPoint struct {
	Longitude float32     `xml:"lon,attr"`
	Latitude  float32     `xml:"lat,attr"`
	Elevation float32     `xml:"ele,omitempty"`
	Time      rfc3339Time `xml:"time,omitempty"`
}

type gpx struct {
	XMLName        xml.Name     `xml:"http://www.topografix.com/GPX/1/1 gpx"`
	SchemaInstance string       `xml:"xmlns:xsi,attr"`
	SchemaLocation string       `xml:"xsi:schemaLocation,attr"`
	Version        float32      `xml:"version,attr"`
	Creator        string       `xml:"creator,attr"`
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

		for _, point := range activity.Trace {
			points = append(points, trackPoint{
				Longitude: point.Longitude,
				Latitude:  point.Latitude,
				Elevation: point.Elevation,
				Time:      rfc3339Time{point.Time},
			})
		}

		data := gpx{
			SchemaInstance: "http://www.w3.org/2001/XMLSchema-instance",
			SchemaLocation: "http://www.topografix.com/GPX/1/1",
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
		flag.Usage()
		os.Exit(1)
	}

	user, err := api.Login(context.Background(), email, password)

	if err != nil {
		Error.Fatal(err)
	}

	activities, err := api.GetActivities(context.Background(), user)

	if err != nil {
		Error.Fatal(err)
	}

	if len(activities) == 0 {
		Error.Fatal(errNoActivities)
	}

	filename := getFilename(time.Now(), "zip")

	if err = archive(filename, activities); err != nil {
		Error.Fatal(err)
	}

	Info.Printf("Activities successfully archived to %s\n", filename)
}
