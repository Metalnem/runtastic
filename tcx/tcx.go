// Package tcx implements exporting Runtastic data in TCX format.
package tcx

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalnem/runtastic/api"
	"github.com/pkg/errors"
)

var schemaLocation = strings.Join([]string{
	"http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2",
	"http://www.garmin.com/xmlschemas/TrainingCenterDatabasev2.xsd",
}, " ")

// Exporter writes TCX data to an output stream.
type Exporter struct {
	w io.Writer
}

type trackPoint struct {
	Time      string   `xml:"Time"`
	Distance  int32    `xml:"DistanceMeters,omitempty"`
	Altitude  float32  `xml:"AltitudeMeters,omitempty"`
	Latitude  *float32 `xml:"Position>LatitudeDegrees,omitempty"`
	Longitude *float32 `xml:"Position>LongitudeDegrees,omitempty"`
	HeartRate *uint8   `xml:"HeartRateBpm>Value,omitempty"`
}

type lap struct {
	StartTime     string       `xml:"StartTime,attr"`
	TotalTime     float64      `xml:"TotalTimeSeconds"`
	Distance      int32        `xml:"DistanceMeters"`
	Calories      int32        `xml:"Calories,omitempty"`
	AvgHeartRate  *int32       `xml:"AverageHeartRateBpm>Value,omitempty"`
	MaxHeartReate *int32       `xml:"MaximumHeartRateBpm>Value,omitempty"`
	Notes         string       `xml:"Notes,omitempty"`
	TriggerMethod string       `xml:"TriggerMethod"`
	TrackPoints   []trackPoint `xml:"Track>Trackpoint"`
}

type activity struct {
	Sport string `xml:"Sport,attr"`
	ID    string `xml:"Id"`
	Lap   lap    `xml:"Lap"`
}

type tcx struct {
	XMLName           xml.Name `xml:"http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2 TrainingCenterDatabase"`
	Version           string   `xml:"version,attr"`
	Creator           string   `xml:"creator,attr"`
	SchemaInstance    string   `xml:"xmlns:xsi,attr"`
	SchemaLocation    string   `xml:"xsi:schemaLocation,attr"`
	UserProfile       string   `xml:"xmlns:ns2,attr"`
	ActivityExtension string   `xml:"xmlns:ns3,attr"`
	ProfileExtension  string   `xml:"xmlns:ns4,attr"`
	ActivityGoals     string   `xml:"xmlns:ns5,attr"`
	Activity          activity `xml:"Activities>Activity"`
}

// NewExporter returns a new exporter that writes to w.
func NewExporter(w io.Writer) *Exporter {
	return &Exporter{w}
}

// Export writes activity in TCX format to the stream.
func (exp *Exporter) Export(a api.Activity) error {
	if _, err := fmt.Fprint(exp.w, xml.Header); err != nil {
		return errors.Wrapf(err, "Failed to export activity %s", a.ID)
	}

	var points []trackPoint

	for _, point := range a.Data {
		tp := trackPoint{
			Time:     point.Time.Format(time.RFC3339),
			Distance: point.Distance,
			Altitude: point.Elevation,
		}

		if point.Latitude > 0 || point.Longitude > 0 {
			tp.Latitude = &point.Latitude
			tp.Longitude = &point.Longitude
		}

		if point.HeartRate > 0 {
			heartRate := point.HeartRate
			tp.HeartRate = &heartRate
		}

		points = append(points, tp)
	}

	startTime := a.StartTime.Format(time.RFC3339)

	lap := lap{
		StartTime:     startTime,
		TotalTime:     a.Duration.Seconds(),
		Distance:      a.Distance,
		Calories:      a.Calories,
		Notes:         a.Notes,
		TriggerMethod: "Manual",
		TrackPoints:   points,
	}

	if a.AvgHeartRate > 0 {
		lap.AvgHeartRate = &a.AvgHeartRate
	}

	if a.MaxHeartReate > 0 {
		lap.MaxHeartReate = &a.MaxHeartReate
	}

	activity := activity{Sport: a.Type.ExportName, ID: startTime, Lap: lap}

	if activity.Sport == "" {
		activity.Sport = "other"
	}

	data := tcx{
		SchemaInstance:    "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLocation:    schemaLocation,
		Version:           "1.0",
		Creator:           "Runtastic Archiver, https://github.com/Metalnem/runtastic",
		UserProfile:       "http://www.garmin.com/xmlschemas/UserProfile/v2",
		ActivityExtension: "http://www.garmin.com/xmlschemas/ActivityExtension/v2",
		ProfileExtension:  "http://www.garmin.com/xmlschemas/ProfileExtension/v1",
		ActivityGoals:     "http://www.garmin.com/xmlschemas/ActivityGoals/v1",
		Activity:          activity,
	}

	encoder := xml.NewEncoder(exp.w)
	encoder.Indent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return errors.Wrapf(err, "Failed to export activity %s", a.ID)
	}

	return nil
}
