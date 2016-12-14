package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetActivity(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/webapps/services/auth/login", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Session{
			UserID:      UserID("id"),
			AccessToken: "token",
			Cookie:      "cookie",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	baseURL = server.URL
	ctx := context.Background()

	if _, err := Login(ctx, "email", "password"); err != nil {
		t.Fatal(err)
	}
}
