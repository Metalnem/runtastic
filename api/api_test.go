package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func handle(pattern string, handler http.HandlerFunc) func() {
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, handler)

	server := httptest.NewServer(mux)
	baseURL = server.URL

	return server.Close
}

func mustParse(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)

	if err != nil {
		panic(err)
	}

	return t
}

func TestLogin(t *testing.T) {
	close := handle("/webapps/services/auth/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"userId":"1519071252","accessToken":"token","Cookie":"cookie"}`)
	})

	defer close()
	session, err := Login(context.Background(), "email", "password")

	if err != nil {
		t.Fatal(err)
	}

	expected := UserID("1519071252")

	if session.UserID != expected {
		t.Fatalf("Expected %s, got %s", expected, session.UserID)
	}
}

func TestGetActivityIDs(t *testing.T) {
	close := handle("/webapps/services/runsessions/v3/sync", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"sessions":[{"id":"3031240871","gpsTraceAvailable":"true"}]}`)
	})

	defer close()
	ids, err := GetActivityIDs(context.Background(), new(Session))

	if err != nil {
		t.Fatal(err)
	}

	if len(ids) != 1 {
		t.Fatalf("Expected single activity, got %d", len(ids))
	}

	expected := ActivityID("3031240871")

	if ids[0] != expected {
		t.Fatalf("Expected %s, got %s", expected, ids[0])
	}
}

func getActivity(t *testing.T, id ActivityID, path string) *Activity {
	url := fmt.Sprintf("/webapps/services/runsessions/v2/%s/details", id)

	close := handle(url, func(w http.ResponseWriter, r *http.Request) {
		file, err := os.Open(path)

		if err != nil {
			t.Fatal(err)
		}

		io.Copy(w, file)
	})

	defer close()
	activity, err := GetActivity(context.Background(), new(Session), id)

	if err != nil {
		t.Fatal(err)
	}

	return activity
}

func assertEquals(t *testing.T, activity, expected *Activity) {
	if !reflect.DeepEqual(activity, expected) {
		t.Fatalf("Expected %v, got %v", expected, activity)
	}
}

func TestGetActivityGPS(t *testing.T) {
	id := ActivityID("1481996726")
	activity := getActivity(t, id, "../static/gps.json")

	expected := &Activity{
		ID:        id,
		Type:      ActivityType{1, "Running", "running"},
		StartTime: time.Unix(1480085018, 0).UTC(),
		EndTime:   time.Unix(1480085041, 0).UTC(),
		Data: []DataPoint{
			{Longitude: 20.470512, Latitude: 44.80998, Elevation: 129.74628, Time: mustParse("2016-11-25T14:43:38Z")},
			{Longitude: 20.47056, Latitude: 44.809906, Elevation: 129.63553, Time: mustParse("2016-11-25T14:43:40Z")},
			{Longitude: 20.470585, Latitude: 44.809803, Elevation: 129.62706, Time: mustParse("2016-11-25T14:43:43Z")},
			{Longitude: 20.470596, Latitude: 44.809734, Elevation: 129.65015, Time: mustParse("2016-11-25T14:43:45Z")},
			{Longitude: 20.470652, Latitude: 44.809635, Elevation: 129.66025, Time: mustParse("2016-11-25T14:43:48Z")},
			{Longitude: 20.470716, Latitude: 44.809586, Elevation: 129.61984, Time: mustParse("2016-11-25T14:43:50Z")},
			{Longitude: 20.47078, Latitude: 44.809513, Elevation: 129.62643, Time: mustParse("2016-11-25T14:43:53Z")},
			{Longitude: 20.47083, Latitude: 44.809456, Elevation: 129.6278, Time: mustParse("2016-11-25T14:43:55Z")},
			{Longitude: 20.470943, Latitude: 44.80939, Elevation: 129.58714, Time: mustParse("2016-11-25T14:43:58Z")},
			{Longitude: 20.47103, Latitude: 44.809315, Elevation: 129.57872, Time: mustParse("2016-11-25T14:44:01Z")},
		},
	}

	assertEquals(t, activity, expected)
}

func TestGetActivityHeartRate(t *testing.T) {
	id := ActivityID("1481996727")
	activity := getActivity(t, id, "../static/heartRate.json")

	expected := &Activity{
		ID:            id,
		Type:          ActivityType{3, "Cycling", "cycling"},
		StartTime:     time.Unix(1482135300, 0).UTC(),
		EndTime:       time.Unix(1482135324, 0).UTC(),
		AvgHeartRate:  76,
		MaxHeartReate: 82,
		Data: []DataPoint{
			{HeartRate: 72, Time: mustParse("2016-12-19T08:15:00Z")},
			{HeartRate: 82, Time: mustParse("2016-12-19T08:15:14Z")},
			{HeartRate: 92, Time: mustParse("2016-12-19T08:15:24Z")},
		},
	}

	assertEquals(t, activity, expected)
}

func TestGetActivityManual(t *testing.T) {
	id := ActivityID("1481996728")
	activity := getActivity(t, id, "../static/manual.json")

	expected := &Activity{
		ID:            id,
		Type:          ActivityType{5, "Other", "other"},
		StartTime:     time.Unix(1483025750, 0).UTC(),
		EndTime:       time.Unix(1483031015, 0).UTC(),
		Calories:      1183,
		Distance:      12000,
		Duration:      3750 * time.Second,
		AvgHeartRate:  152,
		MaxHeartReate: 178,
		Notes:         "Test test test!",
	}

	assertEquals(t, activity, expected)
}
