package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

const (
	appKey     = "com.runtastic.android"
	appSecret  = "T68bA6dHk2ayW1Y39BQdEnUmGqM8Zq1SFZ3kNas3KYDjp471dJNXLcoYWsDBd1mH"
	appVersion = "6.9.2"

	baseURL       = "https://appws.runtastic.com"
	httpTimeout   = 5 * time.Second
	sessionCookie = "_runtastic_appws_session"

	headerAppKey      = "X-App-Key"
	headerAppVersion  = "X-App-Version"
	headerAuthToken   = "X-Auth-Token"
	headerContentType = "Content-Type"
	headerDate        = "X-Date"
)

var (
	errAuthenticationFailed = errors.New("Invalid email address or password")
	errInvalidLoginResponse = errors.New("Invalid login response from server")
)

// UserID is unique user identifier.
type UserID string

// ActivityID is unique activity identifier.
type ActivityID string

// Session contains session data for single authenticated user.
type Session struct {
	UserID      UserID `json:"userId"`
	AccessToken string `json:"accessToken"`
	Cookie      string
}

type loginRequest struct {
	Email      string   `json:"email"`
	Attributes []string `json:"additionalAttributes"`
	Password   string   `json:"password"`
}

type activitiesResponse struct {
	SyncedUntil string `json:"syncedUntil"`
	HasMore     string `json:"moreItemsAvailable"`
	Sessions    []struct {
		ID       ActivityID `json:"id"`
		HasTrace string     `json:"gpsTraceAvailable"`
	} `json:"sessions"`
}

func setHeaders(header http.Header) {
	t := time.Now().Format("2006-01-02 15:04:05")
	s := fmt.Sprintf("--%s--%s--%s--", appKey, appSecret, t)

	hash := sha1.Sum([]byte(s))
	authToken := hex.EncodeToString(hash[:])

	header.Set(headerContentType, "application/json")
	header.Set(headerAppKey, appKey)
	header.Set(headerAppVersion, appVersion)
	header.Set(headerAuthToken, authToken)
	header.Set(headerDate, t)
}

// Login connects to Runtastic API server and authenticates user using given email and password.
func Login(ctx context.Context, email, password string) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

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

	client := new(http.Client)
	resp, err := client.Do(req.WithContext(ctx))

	if err != nil {
		return nil, errors.WithMessage(err, "Failed to connect to Runtastic API server")
	}

	defer resp.Body.Close()

	// For some silly reason, Runtastic API returns 402 instead of 401
	if resp.StatusCode == http.StatusPaymentRequired {
		return nil, errAuthenticationFailed
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.WithMessage(errors.New(resp.Status), "Failed to login")
	}

	var data Session
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, errors.WithMessage(err, errInvalidLoginResponse.Error())
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookie {
			data.Cookie = cookie.Value
		}
	}

	if data.Cookie == "" {
		return nil, errInvalidLoginResponse
	}

	return &data, nil
}

// GetActivities returns list of all activities that have GPS trace available.
func GetActivities(ctx context.Context, session *Session) ([]ActivityID, error) {
	var activities []ActivityID

	syncedUntil := "0"
	hasMore := true

	for hasMore {
		err := func() error {
			newCtx, cancel := context.WithTimeout(ctx, httpTimeout)
			defer cancel()

			url := baseURL + "/webapps/services/runsessions/v3/sync?access_token=" + session.AccessToken
			body := bytes.NewReader([]byte(fmt.Sprintf("{\"syncedUntil\":\"%s\"}", syncedUntil)))
			req, err := http.NewRequest(http.MethodPost, url, body)

			if err != nil {
				return err
			}

			setHeaders(req.Header)
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session.Cookie})

			client := new(http.Client)
			resp, err := client.Do(req.WithContext(newCtx))

			if err != nil {
				return errors.WithMessage(err, "Failed to download list of activities")
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return errors.WithMessage(errors.New(resp.Status), "Failed to download list of activities")
			}

			var data activitiesResponse
			decoder := json.NewDecoder(resp.Body)

			if err = decoder.Decode(&data); err != nil {
				return errors.WithMessage(err, "Invalid activity list response from server")
			}

			for _, session := range data.Sessions {
				if session.HasTrace == "" {
					continue
				}

				var hasTrace bool
				hasTrace, err = strconv.ParseBool(session.HasTrace)

				if err != nil {
					return err
				}

				if hasTrace {
					l := len(activities)
					id := ActivityID(session.ID)

					if l == 0 || activities[l-1] != id {
						activities = append(activities, id)
					}
				}
			}

			syncedUntil = data.SyncedUntil

			if hasMore, err = strconv.ParseBool(data.HasMore); err != nil {
				return err
			}

			return nil
		}()

		if err != nil {
			return nil, err
		}
	}

	return activities, nil
}
