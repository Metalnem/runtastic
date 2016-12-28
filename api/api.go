// Package api implements Runtastic API for downloading activity data.
package api

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"net/http/httputil"

	"github.com/golang/glog"
	"github.com/pkg/errors"
)

const (
	// ToleranceKey is key used to get or set tolerance option in Context passed to GetActivity and GetActivities functions.
	ToleranceKey = RuntasticContextKey("tolerance")

	appKey     = "com.runtastic.android"
	appSecret  = "T68bA6dHk2ayW1Y39BQdEnUmGqM8Zq1SFZ3kNas3KYDjp471dJNXLcoYWsDBd1mH"
	appVersion = "6.9.2"

	httpTimeout   = 30 * time.Second
	sessionCookie = "_runtastic_appws_session"

	headerAppKey      = "X-App-Key"
	headerAppVersion  = "X-App-Version"
	headerAuthToken   = "X-Auth-Token"
	headerContentType = "Content-Type"
	headerDate        = "X-Date"
)

var (
	baseURL = "https://appws.runtastic.com"

	errAuthenticationFailed      = errors.New("Invalid email address or password")
	errInvalidLoginResponse      = errors.New("Invalid login response from server")
	errInvalidActivitiesResponse = errors.New("Invalid activity list response from server")
	errInvalidTime               = errors.New("Invalid time")

	include = []byte(fmt.Sprintf("{%s,%s,%s}",
		`"includeGpsTrace":{"include":"true","version":"1"}`,
		`"includeHeartRateTrace":{"include":"true","version":"1"}`,
		`"includeHeartRateZones":"true"`))
)

// UserID is unique user identifier.
type UserID string

// ActivityID is unique activity identifier.
type ActivityID string

// RuntasticContextKey is the type of keys used in Context.
type RuntasticContextKey string

// Session contains session data for single authenticated user.
type Session struct {
	UserID      UserID `json:"userId"`
	AccessToken string `json:"accessToken"`
	Cookie      string
}

// DataPoint represents single activity data point.
type DataPoint struct {
	Longitude float32
	Latitude  float32
	Elevation float32
	Time      time.Time
	HeartRate uint8
}

type gpsPoint struct {
	Longitude     float32
	Latitude      float32
	Elevation     float32
	Time          time.Time
	SpeedKPH      float32
	Elapsed       time.Duration
	Distance      int32
	ElevationGain int16
	ElevationLoss int16
}

type heartRatePoint struct {
	Time      time.Time
	HeartRate uint8
	Elapsed   time.Duration
	Distance  int32
}

// Activity contains metadata and collection of data points for single activity.
type Activity struct {
	ID        ActivityID
	StartTime time.Time
	EndTime   time.Time
	Data      []DataPoint
}

type loginRequest struct {
	Email                string   `json:"email"`
	AdditionalAttributes []string `json:"additionalAttributes"`
	Password             string   `json:"password"`
}

type activitiesResponse struct {
	SyncedUntil        string   `json:"syncedUntil"`
	MoreItemsAvailable jsonBool `json:"moreItemsAvailable"`
	Sessions           []struct {
		ID                 ActivityID `json:"id"`
		DeletedAt          string     `json:"deletedAt"`
		GPSTraceAvailable  jsonBool   `json:"gpsTraceAvailable"`
		HeartRateAvailable jsonBool   `json:"heartRateAvailable"`
	} `json:"sessions"`
}

type activityResponse struct {
	RunSessions struct {
		ID        ActivityID `json:"id"`
		StartTime jsonTime   `json:"startTime"`
		EndTime   jsonTime   `json:"endTime"`
		GPSData   struct {
			Trace string `json:"trace"`
		} `json:"gpsData"`
		HeartRateData struct {
			Trace string `json:"trace"`
		} `json:"heartRateData"`
	} `json:"runSessions"`
}

func (gps gpsPoint) DataPoint() DataPoint {
	return DataPoint{
		Longitude: gps.Longitude,
		Latitude:  gps.Latitude,
		Elevation: gps.Elevation,
		Time:      gps.Time,
	}
}

func (heartRate heartRatePoint) DataPoint() DataPoint {
	return DataPoint{
		Time:      heartRate.Time,
		HeartRate: heartRate.HeartRate,
	}
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

func dumpResponse(resp *http.Response) {
	if glog.V(1) {
		body, err := httputil.DumpResponse(resp, true)

		if err != nil {
			glog.Fatal(err)
		}

		glog.V(1).Infof("%s", body)
	}
}

// Login connects to Runtastic API server and authenticates user using given email and password.
func Login(ctx context.Context, email, password string) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	b, err := json.Marshal(loginRequest{
		Email:                email,
		AdditionalAttributes: []string{"accessToken"},
		Password:             password,
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
	dumpResponse(resp)

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

// GetActivityIDs returns list of IDs of all activities that have GPS trace available.
func GetActivityIDs(ctx context.Context, session *Session) ([]ActivityID, error) {
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
			dumpResponse(resp)

			if resp.StatusCode != http.StatusOK {
				return errors.WithMessage(errors.New(resp.Status), "Failed to download list of activities")
			}

			var data activitiesResponse
			decoder := json.NewDecoder(resp.Body)

			if err = decoder.Decode(&data); err != nil {
				return errors.WithMessage(err, errInvalidActivitiesResponse.Error())
			}

			for _, session := range data.Sessions {
				if session.DeletedAt == "" {
					l := len(activities)
					id := ActivityID(session.ID)

					if l == 0 || activities[l-1] != id {
						activities = append(activities, id)
					}
				}
			}

			syncedUntil = data.SyncedUntil

			if hasMore, err = data.MoreItemsAvailable.Bool(); err != nil {
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

func decodeTrace(trace string) ([]byte, error) {
	encoded := strings.Split(trace, "\\n")
	var decoded []byte

	for _, line := range encoded {
		b, err := base64.StdEncoding.DecodeString(line)

		if err != nil {
			return nil, err
		}

		decoded = append(decoded, b...)
	}

	return decoded, nil
}

func parseDataPoint(input io.Reader) (gpsPoint, error) {
	var point gpsPoint
	var t timestamp
	var elapsed int32

	r := reader{input, nil}

	r.read(&t)
	r.read(&point.Longitude)
	r.read(&point.Latitude)
	r.read(&point.Elevation)

	var unknown int16
	r.read(&unknown)

	r.read(&point.SpeedKPH)
	r.read(&elapsed)
	r.read(&point.Distance)
	r.read(&point.ElevationGain)
	r.read(&point.ElevationLoss)

	if r.err != nil {
		return gpsPoint{}, r.err
	}

	point.Time = t.toUtcTime()
	point.Elapsed = time.Duration(elapsed) * time.Millisecond

	return point, nil
}

func parseGPSData(trace string) ([]gpsPoint, error) {
	if trace == "" {
		return nil, nil
	}

	decoded, err := decodeTrace(trace)

	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(decoded)
	var size int32

	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	var points []gpsPoint

	for i := 0; i < int(size); i++ {
		point, err := parseDataPoint(buf)

		if err != nil {
			return nil, err
		}

		points = append(points, point)
	}

	return points, nil
}

func parseHeartRate(input io.Reader) (heartRatePoint, error) {
	var point heartRatePoint
	var t timestamp
	var elapsed int32

	r := reader{input, nil}

	r.read(&t)
	r.read(&point.HeartRate)

	var unknown uint8
	r.read(&unknown)

	r.read(&elapsed)
	r.read(&point.Distance)

	if r.err != nil {
		return heartRatePoint{}, r.err
	}

	point.Time = t.toUtcTime()
	point.Elapsed = time.Duration(elapsed) * time.Millisecond

	return point, nil
}

func parseHeartRateData(trace string) ([]heartRatePoint, error) {
	if trace == "" {
		return nil, nil
	}

	decoded, err := decodeTrace(trace)

	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(decoded)
	var size int32

	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	var points []heartRatePoint

	for i := 0; i < int(size); i++ {
		point, err := parseHeartRate(buf)

		if err != nil {
			return nil, err
		}

		points = append(points, point)
	}

	return points, nil
}

func merge(ctx context.Context, gpsData []gpsPoint, heartRateData []heartRatePoint) []DataPoint {
	var data []DataPoint

	if len(gpsData) == 0 {
		for _, heartRate := range heartRateData {
			data = append(data, heartRate.DataPoint())
		}

		return data
	}

	l := len(heartRateData)
	diff := 15 * time.Second

	if tolerance, ok := ctx.Value(ToleranceKey).(int); ok && tolerance > 0 {
		diff = time.Duration(tolerance) * time.Second
	}

	for _, gps := range gpsData {
		point := gps.DataPoint()

		if l > 0 {
			index := sort.Search(l, func(i int) bool {
				return !heartRateData[i].Time.Before(gps.Time)
			})

			hr1 := heartRateData[max(0, index-1)]
			hr2 := heartRateData[min(l-1, index)]

			diff1 := gps.Time.Sub(hr1.Time)
			diff2 := hr2.Time.Sub(gps.Time)

			if diff1 <= diff2 && diff1 <= diff && hr1.HeartRate > 0 {
				point.HeartRate = hr1.HeartRate
			} else if diff2 <= diff1 && diff2 <= diff && hr2.HeartRate > 0 {
				point.HeartRate = hr2.HeartRate
			}
		}

		data = append(data, point)
	}

	return data
}

// GetActivity downloads GPS trace and heart rate data of an activity with given ID.
func GetActivity(ctx context.Context, session *Session, id ActivityID) (*Activity, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/webapps/services/runsessions/v2/%s/details?access_token=%s", baseURL, id, session.AccessToken)
	body := bytes.NewReader(include)
	req, err := http.NewRequest(http.MethodPost, url, body)

	if err != nil {
		return nil, err
	}

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session.Cookie})

	client := new(http.Client)
	resp, err := client.Do(req.WithContext(ctx))

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session.Cookie})

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to download data for activity %s", id)
	}

	defer resp.Body.Close()
	dumpResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(err, "Failed to download data for activity %s", id)
	}

	var data activityResponse
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, errors.Wrapf(err, "Invalid data received from server for activity %s", id)
	}

	gpsData, err := parseGPSData(data.RunSessions.GPSData.Trace)

	if err != nil {
		return nil, errors.Wrapf(err, "Invalid GPS data received from server for activity %s", id)
	}

	heartRateData, err := parseHeartRateData(data.RunSessions.HeartRateData.Trace)

	if err != nil {
		return nil, errors.Wrapf(err, "Invalid heart rate data received from server for activity %s", id)
	}

	activity := Activity{
		ID:        id,
		StartTime: time.Time(data.RunSessions.StartTime),
		EndTime:   time.Time(data.RunSessions.EndTime),
		Data:      merge(ctx, gpsData, heartRateData),
	}

	return &activity, nil
}

// GetActivities retrieves GPS traces and heart rate data for all available activities.
func GetActivities(ctx context.Context, session *Session) ([]Activity, error) {
	ids, err := GetActivityIDs(ctx, session)

	if err != nil {
		return nil, err
	}

	var activities []Activity

	for _, id := range ids {
		activity, err := GetActivity(ctx, session, id)

		if err != nil {
			return nil, err
		}

		activities = append(activities, *activity)
	}

	return activities, nil
}
