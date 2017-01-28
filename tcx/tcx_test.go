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
