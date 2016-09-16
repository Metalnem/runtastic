package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	appKey     = "com.runtastic.android"
	appSecret  = "T68bA6dHk2ayW1Y39BQdEnUmGqM8Zq1SFZ3kNas3KYDjp471dJNXLcoYWsDBd1mH"
	appSession = "_runtastic_appws_session"
	baseURL    = "https://appws.runtastic.com"
	timeFormat = "2006-01-02 15:04:05"
	timeout    = 10 * time.Second
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")
)

type sessionID string

type loginRequest struct {
	Email      string   `json:"email"`
	Attributes []string `json:"additionalAttributes"`
	Password   string   `json:"password"`
}

type authenticatedUser struct {
	UserID      string `json:"userId"`
	AccessToken string `json:"accessToken"`
	Uidt        string `json:"uidt"`
	SessionID   string
}

type activities struct {
	SyncedUntil string    `json:"syncedUntil"`
	HasMore     string    `json:"moreItemsAvailable"`
	Sessions    []session `json:"sessions"`
}

type session struct {
	ID        string `json:"id"`
	DeletedAt string `json:"deletedAt"`
}

func buildAuthToken(t time.Time) string {
	s := fmt.Sprintf("--%s--%s--%s--", appKey, appSecret, t.Format(timeFormat))
	hash := sha1.Sum([]byte(s))

	return hex.EncodeToString(hash[:])
}

func setHeaders(header http.Header) {
	t := time.Now()
	authToken := buildAuthToken(t)

	header.Set("Content-Type", "application/json")
	header.Set("X-App-Key", appKey)
	header.Set("X-App-Version", "6.9.2")
	header.Set("X-Auth-Token", authToken)
	header.Set("X-Date", t.Format(timeFormat))
}

func login(email, password string) (*authenticatedUser, error) {
	b, err := json.Marshal(loginRequest{
		Email:      email,
		Attributes: []string{"accessToken"},
		Password:   password,
	})

	if err != nil {
		return nil, err
	}

	body := bytes.NewReader(b)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/webapps/services/auth/login", body)

	if err != nil {
		return nil, err
	}

	setHeaders(req.Header)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	var data authenticatedUser
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, err
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == appSession {
			data.SessionID = cookie.Value
		}
	}

	return &data, nil
}

func getSessions(user *authenticatedUser) ([]sessionID, error) {
	url := baseURL + "/webapps/services/runsessions/v3/sync?access_token=" + user.AccessToken
	body := bytes.NewReader([]byte(`{"syncedUntil":"0"}`))
	req, err := http.NewRequest(http.MethodPost, url, body)

	if err != nil {
		return nil, err
	}

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: appSession, Value: user.SessionID})

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	var data activities
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, err
	}

	var sessions []sessionID

	for _, session := range data.Sessions {
		if session.DeletedAt == "" {
			sessions = append(sessions, sessionID(session.ID))
		}
	}

	return sessions, nil
}

func main() {
	flag.Parse()

	if *email == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	user, err := login(*email, *password)

	if err != nil {
		log.Fatal(err)
	}

	sessions, err := getSessions(user)

	if err != nil {
		log.Fatal(err)
	}

	for _, session := range sessions {
		fmt.Println(session)
	}
}
