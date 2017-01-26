package main

import (
	"archive/zip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/metalnem/runtastic/api"
	"github.com/metalnem/runtastic/gpx"
	"github.com/pkg/errors"
)

const usage = `Usage of Runtastic Archiver:
  -email string
    	Email (required)
  -password string
    	Password (required)`

var (
	email     = flag.String("email", "", "")
	password  = flag.String("password", "", "")
	tolerance = flag.Int("tolerance", 15, "")

	errMissingCredentials = errors.New("Missing email address or password")
	errNoActivities       = errors.New("There are no activities to backup")
)

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

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}

func export(activities []api.Activity) error {
	filename := getFilename(time.Now(), "zip")
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

		exp := gpx.NewExporter(w)

		if err = exp.Export(activity); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	flag.Parse()

	email, password, err := getCredentials()

	if err != nil {
		fmt.Println(usage)
		os.Exit(1)
	}

	user, err := api.Login(context.Background(), email, password)

	if err != nil {
		glog.Exit(err)
	}

	ctx := context.Background()

	if *tolerance > 0 {
		ctx = context.WithValue(ctx, api.ToleranceKey, *tolerance)
	}

	activities, err := api.GetActivities(ctx, user)

	if err != nil {
		glog.Exit(err)
	}

	if len(activities) == 0 {
		glog.Exit(errNoActivities)
	}

	if err = export(activities); err != nil {
		glog.Exit(err)
	}

	glog.Flush()
}
