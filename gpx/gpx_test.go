package gpx

import (
	"bytes"
	"io/ioutil"
	"testing"
	"time"

	"github.com/metalnem/runtastic/api"
)

func mustParse(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)

	if err != nil {
		panic(err)
	}

	return t
}

func test(t *testing.T, activity api.Activity, path string) {
	var b bytes.Buffer
	exp := NewExporter(&b)

	if err := exp.Export(activity); err != nil {
		t.Fatalf("Failed to export activity: %v", err)
	}

	file, err := ioutil.ReadFile(path)

	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	actual := b.String()
	expected := string(file)

	if actual != expected {
		t.Fatalf("Expected %s, got %s", expected, actual)
	}
}

func TestEmpty(t *testing.T) {
	activity := api.Activity{
		ID:        "1485532823",
		StartTime: mustParse("2010-11-25T18:35:20Z"),
		Notes:     "Test note!",
	}

	test(t, activity, "../static/empty.gpx")
}

func TestGPS(t *testing.T) {
	activity := api.Activity{
		ID:        "1485532823",
		StartTime: mustParse("2016-11-30T14:46:38Z"),
		Data: []api.DataPoint{
			{Longitude: 20.472, Latitude: 44.80873, Elevation: 128.83632, Time: mustParse("2016-11-30T14:47:29Z")},
			{Longitude: 20.47212, Latitude: 44.808666, Elevation: 128.83633, Time: mustParse("2016-11-30T14:47:32Z")},
			{Longitude: 20.472223, Latitude: 44.8086, Elevation: 128.8084, Time: mustParse("2016-11-30T14:47:35Z")},
		},
	}

	test(t, activity, "../static/gps.gpx")
}

func TestHeartRate(t *testing.T) {
	activity := api.Activity{
		ID:        "1485532823",
		StartTime: mustParse("2016-11-30T14:46:38Z"),
		Data: []api.DataPoint{
			{HeartRate: 128, Time: mustParse("2016-11-30T14:47:29Z")},
			{HeartRate: 129, Time: mustParse("2016-11-30T14:47:32Z")},
			{HeartRate: 130, Time: mustParse("2016-11-30T14:47:35Z")},
		},
	}

	test(t, activity, "../static/heartRate.gpx")
}
