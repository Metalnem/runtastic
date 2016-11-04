package main

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

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

type gpx struct {
	XMLName        xml.Name     `xml:"http://www.topografix.com/GPX/1/1 gpx"`
	SchemaInstance string       `xml:"xmlns:xsi,attr"`
	SchemaLocation string       `xml:"xsi:schemaLocation,attr"`
	Version        float32      `xml:"version,attr"`
	Creator        string       `xml:"creator,attr"`
	Time           rfc3339Time  `xml:"metadata>time"`
	TrackPoints    []TrackPoint `xml:"trk>trkseg>trkpt"`
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

func archive(filename string, activities []*Activity) (err error) {
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

		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")

		data := gpx{
			SchemaInstance: "http://www.w3.org/2001/XMLSchema-instance",
			SchemaLocation: "http://www.topografix.com/GPX/1/1",
			Version:        1.1,
			Creator:        "Runtastic Archiver, https://github.com/Metalnem/runtastic",
			Time:           rfc3339Time{activity.StartTime},
			TrackPoints:    activity.GPSTrace,
		}

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

	user, err := Login(context.Background(), email, password)

	if err != nil {
		Error.Fatal(err)
	}

	activities, err := GetActivities(context.Background(), user)

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
