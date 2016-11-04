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

const filenameTimeFormat = "2006-01-02 15.04.05"

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
	ID             ActivityID   `xml:"-"`
	XMLName        xml.Name     `xml:"http://www.topografix.com/GPX/1/1 gpx"`
	XSIName        string       `xml:"xmlns:xsi,attr"`
	SchemaLocation string       `xml:"xsi:schemaLocation,attr"`
	Version        float32      `xml:"version,attr"`
	Creator        string       `xml:"creator,attr"`
	StartTime      rfc3339Time  `xml:"metadata>time"`
	EndTime        time.Time    `xml:"-"`
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

func parseSessionData(data *Activity) *gpx {
	result := &gpx{
		ID:             data.ID,
		XSIName:        "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLocation: "http://www.topografix.com/GPX/1/1",
		Version:        1.1,
		Creator:        "Runtastic Archiver, https://github.com/Metalnem/runtastic",
		StartTime:      rfc3339Time{data.StartTime},
		EndTime:        data.EndTime.Local(),
		TrackPoints:    data.GPSTrace,
	}

	return result
}

func archive(filename string, sessions []*Activity) (err error) {
	file, err := os.Create(filename)

	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s", filename)
	}

	defer checkedClose(file, &err)
	zw := zip.NewWriter(file)
	defer checkedClose(zw, &err)

	for _, session := range sessions {
		time := session.EndTime.Format("20060102_1504")
		filename := fmt.Sprintf("runtastic_%s_Running.gpx", time)
		w, err := zw.Create(filename)

		if err != nil {
			return err
		}

		if _, err = fmt.Fprint(w, xml.Header); err != nil {
			return errors.Wrapf(err, "Failed to save session %s", filename)
		}

		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")

		if err = encoder.Encode(parseSessionData(session)); err != nil {
			return errors.Wrapf(err, "Failed to save session %s", filename)
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

	sessions, err := GetActivities(context.Background(), user)

	if err != nil {
		Error.Fatal(err)
	}

	if len(sessions) == 0 {
		Error.Fatal(err)
	}

	filename := fmt.Sprintf("Runtastic %s.zip", time.Now().Format(filenameTimeFormat))

	if err = archive(filename, sessions); err != nil {
		Error.Fatal(err)
	}

	Info.Printf("Activities successfully archived to %s\n", filename)
}
