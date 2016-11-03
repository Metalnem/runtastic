package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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

const filenameTimeFormat = "2006-01-02 15.04.05"

var (
	email    = flag.String("email", "", "Email (required)")
	password = flag.String("password", "", "Password (required)")

	errMissingCredentials = errors.New("Missing email address or password")
	errNoSessions         = errors.New("There are no activities to backup")

	// Info is used for logging information.
	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

	// Error is used for logging errors.
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
)

type sessionData struct {
	RunSessions struct {
		ID        string `json:"id"`
		StartTime string `json:"startTime"`
		EndTime   string `json:"endTime"`
		GPSData   struct {
			Trace string `json:"trace"`
		} `json:"gpsData"`
	} `json:"runSessions"`
}

type gpx struct {
	ID             ActivityID   `xml:"-"`
	XMLName        xml.Name     `xml:"http://www.topografix.com/GPX/1/1 gpx"`
	XSIName        string       `xml:"xmlns:xsi,attr"`
	SchemaLocation string       `xml:"xsi:schemaLocation,attr"`
	Version        float32      `xml:"version,attr"`
	Creator        string       `xml:"creator,attr"`
	StartTime      rfc3339Time  `xml:"metadata>time"`
	EndTime        time.Time    `xml:"-"`
	TrackPoints    []trackPoint `xml:"trk>trkseg>trkpt"`
}

type trackPoint struct {
	Longitude float32     `xml:"lon,attr"`
	Latitude  float32     `xml:"lat,attr"`
	Elevation float32     `xml:"ele,omitempty"`
	Time      rfc3339Time `xml:"time,omitempty"`
}

type rfc3339Time struct {
	time.Time
}

// MarshalXML is a custom XML marshaller that formats time using RFC3339 format.
func (t rfc3339Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	e.EncodeElement(t.Format(time.RFC3339), start)
	return nil
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

func downloadSessionData(ctx context.Context, user *Session, id ActivityID) (*sessionData, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/webapps/services/runsessions/v2/%s/details?access_token=%s", baseURL, id, user.AccessToken)
	body := bytes.NewReader([]byte(`{"includeGpsTrace":{"include":"true","version":"1"}}`))
	req, err := http.NewRequest(http.MethodPost, url, body)

	if err != nil {
		return nil, err
	}

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: user.Cookie})

	client := new(http.Client)
	resp, err := client.Do(req.WithContext(ctx))

	setHeaders(req.Header)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: user.Cookie})

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

	startTime, err := strconv.ParseInt(data.RunSessions.StartTime, 10, 64)

	if err != nil {
		return nil, errors.Wrapf(err, "Invalid start time %s for session %s", data.RunSessions.StartTime, data.RunSessions.ID)
	}

	endTime, err := strconv.ParseInt(data.RunSessions.EndTime, 10, 64)

	if err != nil {
		return nil, errors.Wrapf(err, "Invalid end time %s for session %s", data.RunSessions.EndTime, data.RunSessions.ID)
	}

	result := &gpx{
		ID:             ActivityID(data.RunSessions.ID),
		XSIName:        "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLocation: "http://www.topografix.com/GPX/1/1",
		Version:        1.1,
		Creator:        "Runtastic Archiver, https://github.com/Metalnem/runtastic",
		StartTime:      rfc3339Time{timestampToTime(startTime).UTC()},
		EndTime:        timestampToTime(endTime),
		TrackPoints:    points,
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

	time := timestampToTime(timestamp).UTC()
	point.Time = rfc3339Time{time}

	return point, nil
}

func timestampToTime(timestamp int64) time.Time {
	return time.Unix(timestamp/1000, timestamp%1000*1000)
}

func downloadAllSessions(ctx context.Context, user *Session) ([]*gpx, error) {
	sessions, err := GetActivities(ctx, user)

	if err != nil {
		return nil, err
	}

	if len(sessions) == 0 {
		return nil, errNoSessions
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
		time := session.EndTime.Format("20060102_1504")
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

	user, err := Login(context.Background(), email, password)

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

	filename := fmt.Sprintf("Runtastic %s.zip", time.Now().Format(filenameTimeFormat))

	if err = archive(filename, sessions); err != nil {
		Error.Fatal(err)
	}

	Info.Printf("Activities successfully archived to %s\n", filename)
}
