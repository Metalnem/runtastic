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

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

const (
	appKeyAndroid = "com.runtastic.android"
	appKeyEmber   = "com.runtastic.ember"

	appSecret = "T68bA6dHk2ayW1Y39BQdEnUmGqM8Zq1SFZ3kNas3KYDjp471dJNXLcoYWsDBd1mH"

	appVersionAndroid = "6.9.2"
	appVersionEmber   = "1.0"

	baseAppURL  = "https://appws.runtastic.com"
	baseHubsURL = "https://hubs.runtastic.com"
	baseWebURL  = "https://www.runtastic.com"

	cookieAppSession = "_runtastic_appws_session"
	cookieWebSession = "_runtastic_session"

	headerAccept      = "Accept"
	headerAppKey      = "X-App-Key"
	headerAppVersion  = "X-App-Version"
	headerAuthToken   = "X-Auth-Token"
	headerContentType = "Content-Type"
	headerDate        = "X-Date"

	timeFormat = "2006-01-02 15:04:05"
	timeout    = 10 * time.Second
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")
)

type sessionID string
type exportID string

type loginRequest struct {
	Email      string   `json:"email"`
	Attributes []string `json:"additionalAttributes"`
	Password   string   `json:"password"`
}

type appUser struct {
	ID          string `json:"userId"`
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
	ID        sessionID `json:"id"`
	DeletedAt string    `json:"deletedAt"`
}

type sample struct {
	Data struct {
		ID sessionID `json:"ID"`
	} `json:"data"`
}

func buildAuthToken(t time.Time) string {
	s := fmt.Sprintf("--%s--%s--%s--", appKeyAndroid, appSecret, t.Format(timeFormat))
	hash := sha1.Sum([]byte(s))

	return hex.EncodeToString(hash[:])
}

func setHeaders(header http.Header) {
	t := time.Now()
	authToken := buildAuthToken(t)

	header.Set(headerContentType, "application/json")
	header.Set(headerAppKey, appKeyAndroid)
	header.Set(headerAppVersion, appVersionAndroid)
	header.Set(headerAuthToken, authToken)
	header.Set(headerDate, t.Format(timeFormat))
}

func loginApp(ctx context.Context, email, password string) (*appUser, error) {
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

	client := new(http.Client)
	resp, err := ctxhttp.Do(ctx, client, req)

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

func loginWeb(ctx context.Context, email, password string) (*webUser, error) {
	params := url.Values{}

	params.Set("user[email]", email)
	params.Set("user[password]", password)
	params.Set("grant_type", "password")

	body := bytes.NewBufferString(params.Encode())
	req, err := http.NewRequest(http.MethodPost, baseWebURL+"/en/d/users/sign_in", body)

	if err != nil {
		return nil, err
	}

	req.Header.Set(headerAccept, "application/json")

	client := new(http.Client)
	resp, err := ctxhttp.Do(ctx, client, req)

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

func login(ctx context.Context, email, password string) (*user, error) {
	app, err := loginApp(ctx, email, password)

	if err != nil {
		return nil, err
	}

	web, err := loginWeb(ctx, email, password)

	if err != nil {
		return nil, err
	}

	return &user{appUser: *app, webUser: *web}, nil
}

func getSessions(ctx context.Context, user *user) ([]sessionID, error) {
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

		client := new(http.Client)
		resp, err := ctxhttp.Do(ctx, client, req)

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

func getExportID(ctx context.Context, user *user, id sessionID) (exportID, error) {
	url := fmt.Sprintf("%s/samples/v2/users/%s/samples/%s", baseHubsURL, user.ID, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return "", err
	}

	req.Header.Set(headerAppKey, appKeyEmber)
	req.Header.Set(headerAppVersion, appVersionEmber)

	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: user.SessionCookie})

	client := &http.Client{Timeout: timeout}
	resp, err := ctxhttp.Do(ctx, client, req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	var data sample
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return "", err
	}

	return exportID(data.Data.ID), nil
}

func main() {
	flag.Parse()

	if *email == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctx, _ := context.WithTimeout(context.Background(), timeout)
	user, err := login(ctx, *email, *password)

	if err != nil {
		log.Fatal(err)
	}

	ctx, _ = context.WithTimeout(context.Background(), timeout)
	sessions, err := getSessions(ctx, user)

	if err != nil {
		log.Fatal(err)
	}

	for _, session := range sessions {
		exportID, err := getExportID(context.TODO(), user, session)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s - %s\n", session, exportID)
	}
}
