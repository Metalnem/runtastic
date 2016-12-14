package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetActivity(t *testing.T) {
	userID := UserID("1519071252")
	activityID := ActivityID("3031240871")

	mux := http.NewServeMux()

	mux.HandleFunc("/webapps/services/auth/login", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Session{
			UserID:      userID,
			AccessToken: "token",
			Cookie:      "cookie",
		})
	})

	mux.HandleFunc("/webapps/services/runsessions/v3/sync", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(activitiesResponse{
			Sessions: []session{{ID: activityID, GPSTraceAvailable: "true"}},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	baseURL = server.URL
	ctx := context.Background()

	session, err := Login(ctx, "email", "password")

	if err != nil {
		t.Fatal(err)
	}

	if session.UserID != userID {
		t.Fatalf("Expected %s, got %s", userID, session.UserID)
	}

	ids, err := GetActivityIDs(ctx, session)

	if err != nil {
		t.Fatal(err)
	}

	if len(ids) != 1 {
		t.Fatalf("Expected single activity, got %d", len(ids))
	}

	if ids[0] != activityID {
		t.Fatalf("Expected %s, got %s", activityID, ids[0])
	}
}
