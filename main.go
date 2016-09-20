package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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

	parallelism = 10
	timeFormat  = "2006-01-02 15:04:05"
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")
	format   = flag.String("format", "gpx", "Optional export format (gpx, tcx or kml, default is gpx)")

	errAuthenticationFailed = errors.New("Invalid email address or password")
	errInvalidFormat        = errors.New("Invalid export format")
)

type sessionID string
type exportID string
type sessionData []byte

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

type result struct {
	data sessionData
	err  error
}

func wrap(data sessionData, err error) result {
	return result{data: data, err: err}
}

func withTimeout(ctx context.Context) context.Context {
	ctx, _ = context.WithTimeout(ctx, 10*time.Second)
	return ctx
}

func getFormat(format string) (string, error) {
	format = strings.ToLower(format)

	if format != "gpx" && format != "tcx" && format != "kml" {
		return "", errInvalidFormat
	}

	return format, nil
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

	// For some silly reason, Runtastic API returns 402 instead of 401
	if resp.StatusCode == http.StatusPaymentRequired {
		return nil, errAuthenticationFailed
	}

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

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errAuthenticationFailed
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieWebSession {
			return &webUser{cookie.Value}, nil
		}
	}

	return nil, errAuthenticationFailed
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

	client := new(http.Client)
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

func downloadSessionData(ctx context.Context, user *user, id sessionID, format string) (sessionData, error) {
	exportID, err := getExportID(ctx, user, id)

	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/en/users/%s/sport-sessions/%s.%s", baseWebURL, user.ID, exportID, format)
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: user.SessionCookie})

	client := new(http.Client)
	resp, err := ctxhttp.Do(ctx, client, req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func downloadAllSessions(ctx context.Context, user *user, format string) ([]sessionData, error) {
	sessions, err := getSessions(withTimeout(ctx), user)

	if err != nil {
		return nil, err
	}

	jobs := make(chan sessionID, len(sessions))
	defer close(jobs)

	for _, session := range sessions {
		jobs <- session
	}

	var data []sessionData
	results := make(chan result)

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := 0; i < parallelism; i++ {
		go func() {
			for job := range jobs {
				select {
				case results <- wrap(downloadSessionData(withTimeout(newCtx), user, job, format)):
				case <-newCtx.Done():
					return
				}
			}
		}()
	}

	for {
		select {
		case result := <-results:
			if result.err != nil {
				return nil, err
			}

			data = append(data, result.data)

			if len(data) == len(sessions) {
				return data, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func main() {
	flag.Parse()

	if *email == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	format, err := getFormat(*format)

	if err != nil {
		log.Fatal(err)
	}

	ctx := withTimeout(context.Background())
	user, err := login(ctx, *email, *password)

	if err != nil {
		log.Fatal(err)
	}

	sessions, err := downloadAllSessions(context.Background(), user, format)

	if err != nil {
		log.Fatal(err)
	}

	for _, data := range sessions {
		fmt.Println(string(data))
	}
}
