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
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	appKey    = "com.runtastic.android"
	appSecret = "T68bA6dHk2ayW1Y39BQdEnUmGqM8Zq1SFZ3kNas3KYDjp471dJNXLcoYWsDBd1mH"

	baseAppURL = "https://appws.runtastic.com"
	baseWebURL = "https://www.runtastic.com"

	cookieAppSession = "_runtastic_appws_session"
	cookieWebSession = "_runtastic_session"

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

type appUser struct {
	UserID      string `json:"userId"`
	AccessToken string `json:"accessToken"`
	SessionID   string
}

type webUser struct {
	SessionCookie string
}

type user struct {
	appUser
	webUser
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

func loginApp(email, password string) (*appUser, error) {
	b, err := json.Marshal(loginRequest{
		Email:      email,
		Attributes: []string{"accessToken"},
		Password:   password,
	})

	if err != nil {
		return nil, err
	}

	body := bytes.NewReader(b)
	req, err := http.NewRequest(http.MethodPost, baseAppURL+"/webapps/services/auth/login", body)

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

	var data appUser
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, err
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieAppSession {
			data.SessionID = cookie.Value
		}
	}

	return &data, nil
}

func loginWeb(email, password string) (*webUser, error) {
	params := url.Values{}

	params.Set("user[email]", email)
	params.Set("user[password]", password)
	params.Set("grant_type", "password")

	client := &http.Client{Timeout: timeout}
	resp, err := client.PostForm(baseWebURL+"/en/d/users/sign_in", params)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieWebSession {
			return &webUser{cookie.Value}, nil
		}
	}

	return nil, errors.New("Missing session cookie in login response")
}

func login(email, password string) (*user, error) {
	app, err := loginApp(email, password)

	if err != nil {
		return nil, err
	}

	web, err := loginWeb(email, password)

	if err != nil {
		return nil, err
	}

	return &user{appUser: *app, webUser: *web}, nil
}

func getSessions(user *user) ([]sessionID, error) {
	var sessions []sessionID

	syncedUntil := "0"
	hasMore := true

	for hasMore {
		url := baseAppURL + "/webapps/services/runsessions/v3/sync?access_token=" + user.AccessToken
		body := bytes.NewReader([]byte(fmt.Sprintf("{\"syncedUntil\":\"%s\"}", syncedUntil)))
		req, err := http.NewRequest(http.MethodPost, url, body)

		if err != nil {
			return nil, err
		}

		setHeaders(req.Header)
		req.AddCookie(&http.Cookie{Name: cookieAppSession, Value: user.SessionID})

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

		for _, session := range data.Sessions {
			if session.DeletedAt == "" {
				l := len(sessions)
				id := sessionID(session.ID)

				if l == 0 || sessions[l-1] != id {
					sessions = append(sessions, id)
				}
			}
		}

		syncedUntil = data.SyncedUntil

		if hasMore, err = strconv.ParseBool(data.HasMore); err != nil {
			return nil, err
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
