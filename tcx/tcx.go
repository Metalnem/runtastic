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

type lap struct {
	StartTime     string     `xml:"StartTime,attr"`
	TotalTime     int32      `xml:"TotalTimeSeconds"`
	Distance      int32      `xml:"DistanceMeters"`
	TriggerMethod string     `xml:"TriggerMethod"`
	TrackPoints   []struct{} `xml:"Track>Trackpoint"`
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
func (exp *Exporter) Export(a api.Activity) (err error) {
	if _, err := fmt.Fprint(exp.w, xml.Header); err != nil {
		return errors.Wrapf(err, "Failed to export activity %s", a.ID)
	}

	startTime := a.StartTime.Format(time.RFC3339)
	lap := lap{StartTime: startTime, TriggerMethod: "Manual"}
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

	if err = encoder.Encode(data); err != nil {
		return errors.Wrapf(err, "Failed to export activity %s", a.ID)
	}

	return nil
}
