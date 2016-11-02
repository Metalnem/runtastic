package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	appKey     = "com.runtastic.android"
	appSecret  = "T68bA6dHk2ayW1Y39BQdEnUmGqM8Zq1SFZ3kNas3KYDjp471dJNXLcoYWsDBd1mH"
	appVersion = "6.9.2"

	baseAppURL  = "https://appws.runtastic.com"
	baseHubsURL = "https://hubs.runtastic.com"

	cookieAppSession = "_runtastic_appws_session"

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
	retryTimeout = 2 * time.Second
	totalTimeout = 15 * time.Second
)

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")

	errAuthenticationFailed = errors.New("Invalid email address or password")
	errMissingCredentials   = errors.New("Missing email address or password")
	errNoSessions           = errors.New("There were no activities to backup")

	// Info is used for logging information.
	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

	// Error is used for logging errors.
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
)

type sessionID string

type loginRequest struct {
	Email                string   `json:"email"`
	AdditionalAttributes []string `json:"additionalAttributes"`
	Password             string   `json:"password"`
}

type user struct {
	ID          string `json:"userId"`
	AccessToken string `json:"accessToken"`
	SessionID   string
}

type activities struct {
	SyncedUntil string    `json:"syncedUntil"`
	HasMore     string    `json:"moreItemsAvailable"`
	Sessions    []session `json:"sessions"`
}

type session struct {
	ID                sessionID `json:"id"`
	DeletedAt         string    `json:"deletedAt"`
	GPSTraceAvailable string    `json:"gpsTraceAvailable"`
}

type sessionData struct {
	RunSessions struct {
		ID        string `json:"id"`
		StartTime string `json:"startTime"`
		GPSData   struct {
			Trace string `json:"trace"`
		} `json:"gpsData"`
	} `json:"runSessions"`
}

type gpx struct {
	ID       sessionID `xml:"-"`
	XMLName  xml.Name  `xml:"gpx"`
	Version  float32   `xml:"version,attr"`
	Creator  string    `xml:"creator,attr"`
	Metadata metadata
	Track    track
}

type metadata struct {
	XMLName xml.Name    `xml:"metadata"`
	Time    rfc3339Time `xml:"time"`
}

type track struct {
	XMLName xml.Name `xml:"trk"`
	Segment trackSegment
}

type trackSegment struct {
	XMLName xml.Name `xml:"trkseg"`
	Points  []trackPoint
}

type trackPoint struct {
	XMLName   xml.Name    `xml:"trkpt"`
	Longitude float32     `xml:"lon,attr"`
	Latitude  float32     `xml:"lat,attr"`
	Elevation float32     `xml:"ele,omitempty"`
	Time      rfc3339Time `xml:"time,omitempty"`
}

type rfc3339Time struct {
	time.Time
}

type reader struct {
	io.Reader
	err error
}

// MarshalXML is a custom XML marshaller that formats time using RFC3339 format.
func (t rfc3339Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	e.EncodeElement(t.Format(time.RFC3339), start)
	return nil
}

func (r *reader) read(data interface{}) {
	if r.err == nil {
		r.err = binary.Read(r.Reader, binary.BigEndian, data)
	}
}

func checkedClose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}

func buildAuthToken(t time.Time) string {
	s := fmt.Sprintf("--%s--%s--%s--", appKey, appSecret, t.Format(timeFormat))
	hash := sha1.Sum([]byte(s))

	return hex.EncodeToString(hash[:])
}

func setHeaders(header http.Header) {
	t := time.Now()
	authToken := buildAuthToken(t)

	header.Set(headerContentType, "application/json")
	header.Set(headerAppKey, appKey)
	header.Set(headerAppVersion, appVersion)
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

func login(ctx context.Context, email, password string) (*user, error) {
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

	var data user
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, errors.WithMessage(err, "Invalid login response from server")
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieAppSession {
			data.SessionID = cookie.Value
		}
	}

	Info.Println("Login successful")

	return &data, nil
}

func getSessions(ctx context.Context, user *user) ([]sessionID, error) {
	var sessions []sessionID

	syncedUntil := "0"
	hasMore := true

	for hasMore {
		err := func() error {
			newCtx, cancel := context.WithTimeout(ctx, httpTimeout)
			defer cancel()

			url := baseAppURL + "/webapps/services/runsessions/v3/sync?access_token=" + user.AccessToken
			body := bytes.NewReader([]byte(fmt.Sprintf("{\"syncedUntil\":\"%s\"}", syncedUntil)))
			req, err := http.NewRequest(http.MethodPost, url, body)

			if err != nil {
				return err
			}

			setHeaders(req.Header)
			req.AddCookie(&http.Cookie{Name: cookieAppSession, Value: user.SessionID})

			client := new(http.Client)
			resp, err := client.Do(req.WithContext(newCtx))

			if err != nil {
				return errors.WithMessage(err, "Failed to download list of activities")
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return errors.WithMessage(errors.New(resp.Status), "Failed to download list of activities")
			}

			var data activities
			decoder := json.NewDecoder(resp.Body)

			if err = decoder.Decode(&data); err != nil {
				return errors.WithMessage(err, "Invalid activity list response from server")
			}

			for _, session := range data.Sessions {
				if session.DeletedAt != "" {
					continue
				}

				var hasTrace bool
				hasTrace, err = strconv.ParseBool(session.GPSTraceAvailable)

				if err != nil {
					return err
				}

				if hasTrace {
					l := len(sessions)
					id := sessionID(session.ID)

					if l == 0 || sessions[l-1] != id {
						sessions = append(sessions, id)
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

	Info.Println("List of activities successfully downloaded")

	return sessions, nil
}

func downloadSessionData(ctx context.Context, user *user, id sessionID) (*sessionData, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/webapps/services/runsessions/v2/%s/details?access_token=%s", baseAppURL, id, user.AccessToken)
	body := bytes.NewReader([]byte(`{"includeGpsTrace":{"include":"true","version":"1"}}`))
	req, err := http.NewRequest(http.MethodPost, url, body)

	if err != nil {
		return nil, err
	}

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: cookieAppSession, Value: user.SessionID})

	client := new(http.Client)
	resp, err := client.Do(req.WithContext(ctx))

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: cookieAppSession, Value: user.SessionID})

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to download session data for session %s", id)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(err, "Failed to download session data for session %s", id)
	}

	var data sessionData
	decoder := json.NewDecoder(resp.Body)

	if err = decoder.Decode(&data); err != nil {
		return nil, errors.Wrapf(err, "Invalid session data received from server for session %s", id)
	}

	if data.RunSessions.ID == "" || data.RunSessions.StartTime == "" || data.RunSessions.GPSData.Trace == "" {
		return nil, errors.Wrapf(err, "Incomplete session data received from server for session %s", id)
	}

	return &data, nil
}

func parseSessionData(data *sessionData) (*gpx, error) {
	encoded := strings.Split(data.RunSessions.GPSData.Trace, "\\n")
	var decoded []byte

	for _, line := range encoded {
		b, err := base64.StdEncoding.DecodeString(line)

		if err != nil {
			return nil, errors.Wrapf(err, "GPS trace for session %s is not a valid Base64 string", data.RunSessions.ID)
		}

		decoded = append(decoded, b...)
	}

	buf := bytes.NewBuffer(decoded)
	var size int32

	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, errors.Wrapf(err, "GPS trace for session %s is invalid", data.RunSessions.ID)
	}

	var points []trackPoint

	for i := 0; i < int(size); i++ {
		point, err := readTrackPoint(buf)

		if err != nil {
			return nil, errors.Wrapf(err, "GPS trace for session %s is invalid", data.RunSessions.ID)
		}

		points = append(points, point)
	}

	timestamp, err := strconv.ParseInt(data.RunSessions.StartTime, 10, 64)

	if err != nil {
		return nil, errors.Wrapf(err, "Invalid start time %s for session %s", data.RunSessions.StartTime, data.RunSessions.ID)
	}

	result := &gpx{
		ID:       sessionID(data.RunSessions.ID),
		Version:  1.1,
		Creator:  "Runtastic Archiver, https://github.com/Metalnem/runtastic",
		Metadata: metadata{Time: timestampToTime(timestamp)},
		Track:    track{Segment: trackSegment{Points: points}},
	}

	return result, nil
}

func readTrackPoint(input io.Reader) (trackPoint, error) {
	var point trackPoint
	var timestamp int64

	unknown := make([]byte, 18)
	r := reader{input, nil}

	r.read(&timestamp)
	r.read(&point.Longitude)
	r.read(&point.Latitude)
	r.read(&point.Elevation)
	r.read(unknown)

	if r.err != nil {
		return trackPoint{}, r.err
	}

	point.Time = timestampToTime(timestamp)

	return point, nil
}

func timestampToTime(timestamp int64) rfc3339Time {
	t := time.Unix(timestamp/1000, timestamp%1000*1000)
	return rfc3339Time{t.UTC()}
}

func downloadAllSessions(ctx context.Context, user *user) ([]*gpx, error) {
	sessions, err := getSessions(ctx, user)

	if err != nil {
		return nil, err
	}

	var data []*gpx

	for _, session := range sessions {
		sessionData, err := downloadSessionData(ctx, user, session)

		if err != nil {
			return nil, err
		}

		gpx, err := parseSessionData(sessionData)

		if err != nil {
			return nil, err
		}

		Info.Printf("Session %s downloaded\n", session)

		data = append(data, gpx)
	}

	return data, nil
}

func archive(filename string, sessions []*gpx) (err error) {
	file, err := os.Create(filename)

	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s", filename)
	}

	defer checkedClose(file, &err)
	zw := zip.NewWriter(file)
	defer checkedClose(zw, &err)

	for _, session := range sessions {
		time := session.Metadata.Time.Format("20060102_1504")
		filename := fmt.Sprintf("runtastic_%s_Running.gpx", time)
		w, err := zw.Create(filename)

		if err != nil {
			return err
		}

		if _, err = fmt.Fprint(w, xml.Header); err != nil {
			return errors.Wrapf(err, "Failed to save session %s", filename)
		}

		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")

		if err = encoder.Encode(session); err != nil {
			return errors.Wrapf(err, "Failed to save session %s", filename)
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

	user, err := login(context.Background(), email, password)

	if err != nil {
		Error.Fatal(err)
	}

	sessions, err := downloadAllSessions(context.Background(), user)

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
