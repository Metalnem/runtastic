package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/metalnem/runtastic/api"
	"github.com/metalnem/runtastic/export"
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

	if err = export.ToGPX(activities); err != nil {
		glog.Exit(err)
	}

	glog.Flush()
}
