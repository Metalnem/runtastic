package gpx

import (
	"bytes"
	"io/ioutil"
	"testing"
	"time"

	"github.com/metalnem/runtastic/api"
)

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
		StartTime: time.Date(2010, 11, 25, 18, 35, 20, 0, time.UTC),
		Type: api.ActivityType{
			ID:          1,
			DisplayName: "Running",
			ExportName:  "running",
		},
	}

	test(t, activity, "../static/empty.gpx")
}
