package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestGetActivity(t *testing.T) {
	id := ActivityID("1481996726")

	close := handle("/webapps/services/runsessions/v2/1481996726/details", func(w http.ResponseWriter, r *http.Request) {
		file, err := os.Open("activity.json")

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

	expected := Activity{
		ID:        id,
		StartTime: time.Unix(1480085018, 0).UTC(),
		EndTime:   time.Unix(1480085041, 0).UTC(),
	}

	if activity.StartTime != expected.StartTime {
		t.Fatalf("Expected %v, got %v", expected.StartTime, activity.StartTime)
	}

	if activity.EndTime != expected.EndTime {
		t.Fatalf("Expected %v, got %v", expected.EndTime, activity.EndTime)
	}
}
