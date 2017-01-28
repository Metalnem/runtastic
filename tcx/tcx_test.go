package tcx

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
	}

	test(t, activity, "../static/tcx/empty.tcx")
}

func TestManual(t *testing.T) {
	activity := api.Activity{
		ID:            "1485608013",
		Type:          api.ActivityType{ID: 1, DisplayName: "Running", ExportName: "running"},
		StartTime:     mustParse("2016-12-10T17:32:40Z"),
		Calories:      1250,
		Distance:      9458,
		Duration:      4250 * time.Second,
		AvgHeartRate:  156,
		MaxHeartReate: 182,
		Notes:         "Test test test!",
	}

	test(t, activity, "../static/tcx/manual.tcx")
}
