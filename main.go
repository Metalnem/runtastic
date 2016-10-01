package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
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

	headerAccept             = "Accept"
	headerAppKey             = "X-App-Key"
	headerAppVersion         = "X-App-Version"
	headerAuthToken          = "X-Auth-Token"
	headerContentDisposition = "Content-Disposition"
	headerContentType        = "Content-Type"
	headerDate               = "X-Date"

	outputFormat = "2006-01-02 15.04.05"
	timeFormat   = "2006-01-02 15:04:05"

	httpTimeout  = 5 * time.Second
	retryTimeout = 1 * time.Second
	totalTimeout = 15 * time.Second
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")
	format   = flag.String("format", "gpx", "Optional export format (gpx, tcx or kml)")

	errAuthenticationFailed = errors.New("Invalid email address or password")
	errInvalidFormat        = errors.New("Invalid export format")
	errMissingCredentials   = errors.New("Missing email address or password")
	errMissingFilename      = errors.New("Failed to retrieve activity name from the server")
	errNoSessions           = errors.New("There were no activities to backup")

	// Info is used for logging information.
	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

	// Error is used for logging errors.
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
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

type sessionData struct {
	Filename string
	Data     []byte
}

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
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

func getCredentials() (string, string, error) {
	email := *email
	password := *password

	if email != "" && password != "" {
		return email, password, nil
	}

	email = os.Getenv("RUNTASTIC_EMAIL")
	password = os.Getenv("RUNTASTIC_PASSWORD")

	if email != "" && password != "" {
		return email, password, nil
	}

	return "", "", errMissingCredentials
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
	resp, err := client.Do(req.WithContext(ctx))

	if err != nil {
		return nil, errors.WithMessage(err, "Failed to connect to Runtastic server")
	}

	defer resp.Body.Close()

	// For some silly reason, Runtastic API returns 402 instead of 401
	if resp.StatusCode == http.StatusPaymentRequired {
		return nil, errAuthenticationFailed
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.WithMessage(errors.New(resp.Status), "Failed to login")
	}

	var data appUser
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, errors.WithMessage(err, "Invalid login response from server")
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
	resp, err := client.Do(req.WithContext(ctx))

	if err != nil {
		return nil, errors.WithMessage(err, "Failed to connect to Runtastic server")
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errAuthenticationFailed
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.WithMessage(errors.New(resp.Status), "Failed to login")
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

	Info.Println("Application login successful")

	web, err := loginWeb(ctx, email, password)

	if err != nil {
		return nil, err
	}

	Info.Println("Web login successful")

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
		resp, err := client.Do(req.WithContext(ctx))

		if err != nil {
			return nil, errors.WithMessage(err, "Failed to download list of activities")
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, errors.WithMessage(errors.New(resp.Status), "Failed to download list of activities")
		}

		var data activities
		decoder := json.NewDecoder(resp.Body)

		if err = decoder.Decode(&data); err != nil {
			return nil, errors.WithMessage(err, "Invalid activity list response from server")
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

	Info.Println("List of activities successfully downloaded")

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
	resp, err := client.Do(req.WithContext(ctx))

	if err != nil {
		return "", errors.Wrapf(err, "Failed to retrieve export ID for session %s", id)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.Wrapf(errors.New(resp.Status), "Failed to retrieve export ID for session %s", id)
	}

	var data sample
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return "", errors.Wrapf(err, "Invalid export ID response from server for session %s", id)
	}

	return exportID(data.Data.ID), nil
}

func downloadSessionData(ctx context.Context, user *user, id sessionID, format string) (*sessionData, error) {
	exportID, err := getExportID(ctx, user, id)

	if err != nil {
		return nil, err
	}

	Info.Printf("Export ID for session %s is %s\n", id, exportID)

	url := fmt.Sprintf("%s/en/users/%s/sport-sessions/%s.%s", baseWebURL, user.ID, exportID, format)
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: cookieWebSession, Value: user.SessionCookie})

	client := new(http.Client)
	resp, err := client.Do(req.WithContext(ctx))

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to download session data for session %s", id)
	}

	defer resp.Body.Close()

	h := resp.Header.Get(headerContentDisposition)
	_, params, err := mime.ParseMediaType(h)

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to download session data for session %s", id)
	}

	filename := params["filename"]

	if filename == "" {
		return nil, errMissingFilename
	}

	data, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, errors.Wrapf(err, "Invalid session data received from server for session %s", id)
	}

	Info.Printf("Session %s downloaded\n", filename)

	return &sessionData{Filename: filename, Data: data}, nil
}

func downloadAllSessions(ctx context.Context, user *user, format string) ([]*sessionData, error) {
	newCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	sessions, err := getSessions(newCtx, user)

	cancel()

	if err != nil {
		return nil, err
	}

	var data []*sessionData

	for _, session := range sessions {
		for {
			newCtx, cancel := context.WithTimeout(ctx, httpTimeout)
			sessionData, err := downloadSessionData(newCtx, user, session, format)

			cancel()

			if err != nil {
				return nil, err
			}

			data = append(data, sessionData)
		}
	}

	return data, nil
}

func archive(filename string, sessions []*sessionData) (err error) {
	file, err := os.Create(filename)

	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s", filename)
	}

	defer checkedClose(file, &err)
	zw := zip.NewWriter(file)
	defer checkedClose(zw, &err)

	for _, session := range sessions {
		w, err := zw.Create(session.Filename)

		if err != nil {
			return err
		}

		if _, err = w.Write(session.Data); err != nil {
			return errors.Wrapf(err, "Failed to save session %s", session.Filename)
		}
	}

	return nil
}

func main() {
	flag.Parse()

	email, password, err := getCredentials()

	if err != nil {
		flag.Usage()
		os.Exit(1)
	}

	format, err := getFormat(*format)

	if err != nil {
		Error.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	user, err := login(ctx, email, password)

	cancel()

	if err != nil {
		Error.Fatal(err)
	}

	sessions, err := downloadAllSessions(context.Background(), user, format)

	if err != nil {
		Error.Fatal(err)
	}

	if len(sessions) == 0 {
		Error.Fatal(err)
	}

	filename := fmt.Sprintf("Runtastic %s.zip", time.Now().Format(outputFormat))

	if err = archive(filename, sessions); err != nil {
		Error.Fatal(err)
	}

	Info.Printf("Activities successfully archived to %s\n", filename)
}
