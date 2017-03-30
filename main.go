package main

import (
	"archive/zip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/metalnem/runtastic/api"
	"github.com/metalnem/runtastic/gpx"
	"github.com/metalnem/runtastic/tcx"
	"github.com/pkg/errors"
)

const usage = `Usage of Runtastic Archiver:
  -email string
    	Email (required)
  -password string
    	Password (required)
  -format string
    	Output format (gpx or tcx)`

var (
	email     = flag.String("email", "", "")
	password  = flag.String("password", "", "")
	format    = flag.String("format", "gpx", "")
	tolerance = flag.Int("tolerance", 15, "")

	errMissingCredentials = errors.New("Missing email address or password")
	errNoActivities       = errors.New("There are no activities to backup")
	errInvalidFormat      = errors.New("Invalid output format")
)

type exporter interface {
	Export(api.Activity) error
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

func formatTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15.04.05")
}

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}

func export(activities []api.Activity, exp func(io.Writer) exporter, ext string) error {
	filename := fmt.Sprintf("Runtastic %s.%s", formatTime(time.Now()), "zip")
	file, err := os.Create(filename)

	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s", filename)
	}

	defer checkedClose(file, &err)
	zw := zip.NewWriter(file)
	defer checkedClose(zw, &err)

	for _, activity := range activities {
		filename := fmt.Sprintf("Runtastic %s %s.%s", formatTime(activity.EndTime), activity.Type.DisplayName, ext)

		header := zip.FileHeader{
			Name:   filename,
			Method: zip.Deflate,
		}

		header.SetModTime(time.Now())
		w, err := zw.CreateHeader(&header)

		if err != nil {
			return err
		}

		exp := exp(w)

		if err = exp.Export(activity); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	flag.Parse()

	ext := strings.ToLower(*format)
	var exp func(io.Writer) exporter

	switch ext {
	case "gpx":
		exp = func(w io.Writer) exporter {
			return gpx.NewExporter(w)
		}
	case "tcx":
		exp = func(w io.Writer) exporter {
			return tcx.NewExporter(w)
		}
	default:
		glog.Exit(errInvalidFormat)
	}

	email, password, err := getCredentials()

	if err != nil {
		fmt.Println(usage)
		os.Exit(1)
	}

	session, err := api.Login(context.Background(), email, password)

	if err != nil {
		glog.Exit(err)
	}

	session.Options.Tolerance = *tolerance

	ctx := context.Background()
	activities, err := session.GetActivities(ctx)

	if err != nil {
		glog.Exit(err)
	}

	if len(activities) == 0 {
		glog.Exit(errNoActivities)
	}

	if err = export(activities, exp, ext); err != nil {
		glog.Exit(err)
	}

	glog.Flush()
}
